#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["python-dotenv", "pyvmomi"]
# ///

import ssl
import atexit
import json
import logging
import os
import re  # For sanitizing filename
from getpass import getpass
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pyvim import connect
from pyVmomi import vim, vmodl

# --- Config ---
env_path = Path(__file__).resolve().parent / ".env"
load_dotenv(dotenv_path=env_path)

DATACENTER_NAME_env = os.getenv("DATACENTER_NAME", "DefaultDatacenter")
# Sanitize DATACENTER_NAME for use in filename
DATACENTER_NAME = re.sub(r'[^\w_.)( -]', '',
                         DATACENTER_NAME_env)  # Keep alphanumeric, underscore, dot, parens, space, hyphen
if not DATACENTER_NAME:  # If sanitization results in empty string
    DATACENTER_NAME = "DefaultDatacenter"

VC_USER = os.getenv("VCENTER_USER")
VC_PASSWORD_ENV = os.getenv("VCENTER_PASSWORD")  # Can be empty if prompting
VC_HOSTS_STRING = os.getenv("VCENTER_HOSTS", "")
VC_HOSTS = [h.strip() for h in VC_HOSTS_STRING.split(",") if h.strip()]
VC_PORT = int(os.getenv("VCENTER_PORT", 443))

VMWARE_DISABLE_SSL_str = os.getenv("VMWARE_DISABLE_SSL_VERIFICATION", "True").lower()
DISABLE_SSL_VERIFICATION = VMWARE_DISABLE_SSL_str == "true"

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logger = logging.getLogger(__name__)

if not all([VC_USER, VC_HOSTS]):  # VC_PASSWORD can be prompted
    logger.error("Missing VCENTER_USER or VCENTER_HOSTS in .env file. Exiting.")
    exit(1)

if DISABLE_SSL_VERIFICATION:
    logger.warning("VMware SSL CERTIFICATE VERIFICATION IS DISABLED. "
                   "This is a security risk and NOT recommended for production.")


# --- Utility: fast property collector ---
# (collect_properties function remains the same as your last working version)
def collect_properties(si, obj_type, properties_to_fetch, container_view=None):
    content = si.RetrieveContent()
    view = container_view
    destroy_view = False
    if not view:
        logger.debug(f"Creating new ContainerView for {obj_type}")
        view = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)
        destroy_view = True

    obj_spec = vmodl.query.PropertyCollector.ObjectSpec(
        obj=view, skip=True,
        selectSet=[
            vmodl.query.PropertyCollector.TraversalSpec(
                name="traverseView", path="view", skip=False, type=view.__class__
            )
        ]
    )
    prop_spec = vmodl.query.PropertyCollector.PropertySpec(
        type=obj_type, all=False, pathSet=properties_to_fetch
    )
    filter_spec = vmodl.query.PropertyCollector.FilterSpec(
        objectSet=[obj_spec], propSet=[prop_spec]
    )
    results = []
    try:
        props = content.propertyCollector.RetrievePropertiesEx(
            specSet=[filter_spec], options=vmodl.query.PropertyCollector.RetrieveOptions()
        )
        while props:
            for o in props.objects:
                result = {"obj": o.obj}
                for p in o.propSet:
                    result[p.name] = p.val
                if hasattr(o, 'missingSet') and o.missingSet:
                    for missing in o.missingSet:
                        # Use a more resilient way to get fault message
                        fault_message = "N/A"
                        if hasattr(missing.fault, 'faultMessage') and missing.fault.faultMessage:
                            fault_message = _get_localizable_message(missing.fault.faultMessage)
                        elif hasattr(missing.fault, 'msg'):
                            fault_message = missing.fault.msg
                        logger.debug(
                            f"Property {missing.path} missing for {o.obj} ({obj_type.__name__}): {fault_message}")
                        result[missing.path] = None
                results.append(result)
            token = getattr(props, 'token', None)
            if token:
                props = content.propertyCollector.ContinueRetrievePropertiesEx(token=token)
            else:
                break
    except vmodl.query.InvalidProperty as e:
        fault_message = e.msg
        if hasattr(e, 'faultMessage') and e.faultMessage:
            fault_message = _get_localizable_message(e.faultMessage)
        logger.error(f"InvalidProperty error during collection for {obj_type.__name__} (property path: '{e.name}'). "
                     f"Details: {fault_message}", exc_info=False)
    except Exception as e:
        logger.error(f"Error during property collection for {obj_type.__name__}: {e}", exc_info=True)
    finally:
        if destroy_view and view:
            logger.debug(f"Destroying ContainerView for {obj_type.__name__}")
            view.Destroy()
    return results


def _get_localizable_message(fault_messages):
    """Extracts message from LocalizableMessage array if possible."""
    if isinstance(fault_messages, list) and fault_messages:
        return fault_messages[0].message
    return str(fault_messages)


# --- vCenter connect ---
# (connect_to_vcenter function remains the same)
def connect_to_vcenter(host, user, password, port, disable_ssl):
    ssl_ctx = None
    if disable_ssl:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        si = connect.SmartConnect(host=host, user=user, pwd=password, port=port, sslContext=ssl_ctx)
        logger.info(f"Connected to vCenter: {host}")
        return si
    except Exception as e:
        logger.error(f"Failed to connect to {host}: {e}", exc_info=True)
        return None


# --- Inventory logic ---
def collect_inventory_from_vcenter(vcenter_host, user, password, port, disable_ssl):
    si = connect_to_vcenter(vcenter_host, user, password, port, disable_ssl)
    if not si:
        return None

    content = si.RetrieveContent()
    inventory_data = {
        "vcenter": vcenter_host, "datacenter_name": DATACENTER_NAME,
        "clusters": [], "standalone_hosts": []
    }

    cluster_view = None
    host_view = None
    vm_view = None

    try:
        logger.info(f"[{vcenter_host}] Creating container views...")
        cluster_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.ClusterComputeResource], True)
        host_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.HostSystem], True)
        vm_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)

        logger.info(f"[{vcenter_host}] Fetching cluster properties...")
        cluster_props_to_fetch = [
            "name", "host",
            "configuration.dasConfig.enabled", "configuration.drsConfig.defaultVmBehavior"
            # Removed summary properties that caused errors. Counts will be calculated.
        ]
        clusters_data = collect_properties(si, vim.ClusterComputeResource, cluster_props_to_fetch, cluster_view)
        if not clusters_data:
            logger.warning(
                f"[{vcenter_host}] No cluster data was fetched. This might be due to an error, no clusters existing, or permissions.")

        logger.info(f"[{vcenter_host}] Fetching host properties...")
        host_props_to_fetch = [
            "name", "summary.hardware.uuid", "config.product.fullName",
            "summary.hardware.vendor", "summary.hardware.model",
            "summary.hardware.otherIdentifyingInfo",  # For Serial Number
            "summary.hardware.numCpuCores", "summary.hardware.numCpuPkgs",
            "summary.hardware.numCpuThreads", "summary.hardware.cpuMhz",
            "summary.hardware.memorySize", "summary.hardware.numNics",
            "runtime.connectionState", "runtime.powerState", "runtime.inMaintenanceMode",
            "summary.quickStats.overallCpuUsage", "summary.quickStats.overallMemoryUsage",
            "parent", "vm",  # "vm" property is a list of VM MORs on the host
            "config.network.pnic", "config.network.vswitch", "config.network.portgroup",
            "config.network.vnic", "config.network.dnsConfig.hostName", "config.network.dnsConfig.domainName"
        ]
        hosts_data = collect_properties(si, vim.HostSystem, host_props_to_fetch, host_view)

        logger.info(f"[{vcenter_host}] Fetching VM properties...")
        vm_props_to_fetch = [  # (No changes here from last working version, ensure it's complete)
            "name", "config.instanceUuid", "config.uuid", "summary.config.guestFullName",
            "guest.hostName", "guest.ipAddress", "guest.net", "runtime.powerState",
            "guest.toolsStatus", "guest.toolsVersion", "config.hardware.numCPU",
            "config.hardware.numCoresPerSocket", "config.hardware.memoryMB",
            "config.hardware.device", "summary.storage.committed", "summary.storage.uncommitted",
            "summary.storage.timestamp", "runtime.host", "summary.config.vmPathName",
            "config.annotation", "datastore", "resourcePool", "config.createDate", "config.version"
        ]
        vms_data = collect_properties(si, vim.VirtualMachine, vm_props_to_fetch, vm_view)

        host_map = {h_data["obj"]: h_data for h_data in hosts_data}
        host_to_vms_map = {}
        for vm_item in vms_data:
            host_mor = vm_item.get("runtime.host")
            if host_mor:
                host_to_vms_map.setdefault(host_mor, []).append(vm_item)

        logger.info(f"[{vcenter_host}] Processing collected data...")
        clustered_host_mors = set()
        if clusters_data:
            for cluster_item in clusters_data:
                cluster_name = cluster_item.get("name", "N/A")
                vm_count_in_cluster = 0
                host_mor_list_for_this_cluster = cluster_item.get("host", [])
                for host_mor_in_cluster in host_mor_list_for_this_cluster:
                    vm_count_in_cluster += len(host_to_vms_map.get(host_mor_in_cluster, []))

                cluster_info = {
                    "name": cluster_name,
                    "datacenter_name": DATACENTER_NAME,
                    "drs_status": str(cluster_item.get("configuration.drsConfig.defaultVmBehavior", "N/A")),
                    "ha_status": cluster_item.get("configuration.dasConfig.enabled", False),
                    "total_hosts_in_cluster": len(host_mor_list_for_this_cluster),
                    "total_vms_in_cluster": vm_count_in_cluster,
                    "hosts": []
                }
                for host_mor in host_mor_list_for_this_cluster:
                    clustered_host_mors.add(host_mor)
                    host_detail_data = host_map.get(host_mor)
                    if host_detail_data:
                        cluster_info["hosts"].append(
                            process_host_and_vms(host_detail_data, host_to_vms_map.get(host_mor, []), cluster_name))
                inventory_data["clusters"].append(cluster_info)
        else:
            logger.info(
                f"[{vcenter_host}] No cluster data to process. All hosts will be treated as standalone if found.")

        for host_mor, host_detail_data in host_map.items():
            if host_mor not in clustered_host_mors:
                inventory_data["standalone_hosts"].append(
                    process_host_and_vms(host_detail_data, host_to_vms_map.get(host_mor, []), None))

    except Exception as e:
        logger.error(f"[{vcenter_host}] Error during inventory collection: {e}", exc_info=True)
    finally:
        if cluster_view: cluster_view.Destroy()
        if host_view: host_view.Destroy()
        if vm_view: vm_view.Destroy()
        if si:
            try:
                connect.Disconnect(si)
                logger.info(f"Disconnected from vCenter: {vcenter_host}")
            except Exception as e_disc:
                logger.warning(f"Error during disconnect from {vcenter_host}: {e_disc}")
    return inventory_data


# (process_host_network_details remains the same as last version)
def process_host_network_details(host_data):
    network_details = {
        "physical_nics": [], "virtual_switches": [], "port_groups": [], "vmkernel_nics": [],
        "dns_hostname": getattr(host_data.get("config.network.dnsConfig"), 'hostName', "N/A") if host_data.get(
            "config.network.dnsConfig") else "N/A",
        "dns_domain": getattr(host_data.get("config.network.dnsConfig"), 'domainName', "N/A") if host_data.get(
            "config.network.dnsConfig") else "N/A"
    }
    for pnic in host_data.get("config.network.pnic", []):
        speed_mb = getattr(pnic.linkSpeed, 'speedMb', 'N/A') if hasattr(pnic, 'linkSpeed') and pnic.linkSpeed else 'N/A'
        network_details["physical_nics"].append({
            "device_name": pnic.device, "mac_address": pnic.mac, "driver": getattr(pnic, 'driver', 'N/A'),
            "link_speed_mb": speed_mb, "pci": pnic.pci
        })
    for vswitch in host_data.get("config.network.vswitch", []):
        network_details["virtual_switches"].append({
            "name": vswitch.name, "num_ports": vswitch.numPorts,
            "uplinks": [pnic_key for pnic_key in getattr(vswitch, 'pnic', [])],
            "mtu": getattr(vswitch, 'mtu', 'N/A')
        })
    for pg in host_data.get("config.network.portgroup", []):
        network_details["port_groups"].append({
            "name": pg.spec.name, "vlan_id": pg.spec.vlanId,
            "vswitch_name": pg.spec.vswitchName, "key": pg.key
        })
    for vnic in host_data.get("config.network.vnic", []):
        ip_config = getattr(vnic.spec, 'ip', None)
        services_enabled = []
        # Simple check for management, more complex service detection omitted for brevity
        if getattr(vnic.spec, 'managementTrafficEnabled', False):  # Example, may not be standard
            services_enabled.append("management")
        network_details["vmkernel_nics"].append({
            "device_name": vnic.device, "portgroup_name": vnic.portgroup,
            "ip_address": ip_config.ipAddress if ip_config else "N/A",
            "subnet_mask": ip_config.subnetMask if ip_config else "N/A",
            "dhcp_enabled": ip_config.dhcp if ip_config and hasattr(ip_config, 'dhcp') else "N/A",
            "mac_address": vnic.spec.mac, "mtu": vnic.spec.mtu,
            "services_enabled": services_enabled
        })
    return network_details


# --- MODIFIED process_host_and_vms ---
def process_host_and_vms(host_data, vms_on_host_data, cluster_name=None):
    num_cpu_pkgs_val = host_data.get("summary.hardware.numCpuPkgs")
    num_cpu_pkgs = num_cpu_pkgs_val if num_cpu_pkgs_val and num_cpu_pkgs_val > 0 else 1
    num_cpu_cores_val = host_data.get("summary.hardware.numCpuCores")
    num_cpu_cores = num_cpu_cores_val if num_cpu_cores_val else 0

    # Extract Serial Number
    serial_number = "N/A"
    other_identifying_info = host_data.get("summary.hardware.otherIdentifyingInfo", [])
    if other_identifying_info:
        for id_info in other_identifying_info:
            if hasattr(id_info, 'identifierType') and id_info.identifierType is not None:
                # Common keys for serial numbers: ServiceTag, SerialNumber, EnclosureSerialNumber, AssetTag
                if id_info.identifierType.key in ['ServiceTag', 'SerialNumber', 'BaseboardSerialNumber',
                                                  'ChassisSerialNumber']:
                    serial_number = id_info.identifierValue
                    break  # Take the first one found among these common types
        if serial_number == "N/A" and other_identifying_info:  # Fallback if specific keys not found
            # Try to find any that might look like a serial, or just take the first one as a guess
            # This part can be heuristic. For now, if common tags aren't found, it remains N/A.
            pass

    host_summary = {
        "name": host_data.get("name", "N/A"),
        "host_uuid": host_data.get("summary.hardware.uuid", "N/A"),
        "serial_number": serial_number,  # Added Serial Number
        "esxi_version": host_data.get("config.product.fullName", "N/A"),
        "manufacturer": host_data.get("summary.hardware.vendor", "N/A"),
        "model": host_data.get("summary.hardware.model", "N/A"),
        "cpu_sockets": num_cpu_pkgs_val,
        "cpu_cores_per_socket": num_cpu_cores // num_cpu_pkgs if num_cpu_pkgs > 0 and num_cpu_cores > 0 else num_cpu_cores,
        "total_cpu_cores": num_cpu_cores,
        "total_cpu_threads": host_data.get("summary.hardware.numCpuThreads", "N/A"),
        "cpu_mhz_per_core": host_data.get("summary.hardware.cpuMhz", "N/A"),
        "total_memory_gb": round(host_data.get("summary.hardware.memorySize", 0) / (1024 ** 3), 2),
        "num_nics": host_data.get("summary.hardware.numNics", "N/A"),
        "power_state": str(host_data.get("runtime.powerState", "N/A")),
        "connection_state": str(host_data.get("runtime.connectionState", "N/A")),
        "in_maintenance_mode": host_data.get("runtime.inMaintenanceMode", False),
        "quick_stats_overall_cpu_usage_mhz": host_data.get("summary.quickStats.overallCpuUsage", "N/A"),
        "quick_stats_overall_memory_usage_mb": host_data.get("summary.quickStats.overallMemoryUsage", "N/A"),
        "total_vms_on_host": len(host_data.get("vm", [])),  # Added VM count for this host
        "cluster_name": cluster_name,
        "datacenter_name": DATACENTER_NAME,
        "network_configuration": process_host_network_details(host_data),
        "vms": []
    }
    for vm_item_data in vms_on_host_data:
        vm_summary = process_vm_details(vm_item_data, cluster_name, host_summary["name"])
        host_summary["vms"].append(vm_summary)
    return host_summary


# (process_vm_details function remains the same as your last working version)
def process_vm_details(vm_data, cluster_name, host_name):
    num_cpu = vm_data.get("config.hardware.numCPU", 0)
    cores_per_socket_val = vm_data.get("config.hardware.numCoresPerSocket")
    cores_per_socket = cores_per_socket_val if cores_per_socket_val and cores_per_socket_val > 0 else 1
    total_cores = num_cpu * cores_per_socket if num_cpu > 0 else "N/A"

    networks = []
    all_ip_addresses = []
    guest_nics = vm_data.get("guest.net", [])
    if guest_nics:
        for nic_info in guest_nics:
            nic_ips = getattr(nic_info, 'ipAddress', [])
            nic_entry = {
                "mac_address": getattr(nic_info, 'macAddress', "N/A"),
                "network_label_from_guest": getattr(nic_info, 'network', "N/A"),
                "connected_in_guest": getattr(nic_info, 'connected', False),
                "ip_addresses": list(filter(None, nic_ips)) if nic_ips else []
            }
            networks.append(nic_entry)
            if nic_ips: all_ip_addresses.extend(ip for ip in nic_ips if ip)

    vm_devices = vm_data.get("config.hardware.device", [])
    vnic_configs_from_devices = []
    for device in vm_devices:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            network_name_from_backing = "N/A"
            backing_type = device.backing.__class__.__name__
            vlan_info_str = "N/A"
            connected_at_vswitch = getattr(device.connectable, 'connected', False)

            if isinstance(device.backing, vim.vm.device.VirtualEthernetCard.NetworkBackingInfo):
                network_name_from_backing = device.backing.deviceName
                vlan_info_str = f"Standard PortGroup: {network_name_from_backing}"
            elif isinstance(device.backing, vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo):
                try:
                    pg_key = device.backing.port.portgroupKey
                    network_name_from_backing = f"DVPortGroup Key: {pg_key}"
                    vlan_info_str = f"DVS PortGroup Key: {pg_key}"
                except AttributeError:
                    network_name_from_backing = "DVS Port Info (details N/A)"

            matched_guest_nic = next(
                (n for n in networks if n["mac_address"] == device.macAddress and n["mac_address"] != "N/A"), None)
            if matched_guest_nic:
                matched_guest_nic["vcenter_network_name"] = network_name_from_backing
                matched_guest_nic["vnic_label"] = device.deviceInfo.label
                matched_guest_nic["backing_type"] = backing_type
                matched_guest_nic["vlan_info_summary"] = vlan_info_str
                matched_guest_nic["connected_at_vswitch"] = connected_at_vswitch
            else:
                vnic_configs_from_devices.append({
                    "mac_address": device.macAddress, "vnic_label": device.deviceInfo.label,
                    "vcenter_network_name": network_name_from_backing,
                    "backing_type": backing_type, "vlan_info_summary": vlan_info_str,
                    "connected_at_vswitch": connected_at_vswitch,
                    "network_label_from_guest": "N/A (or no MAC match in guest.net)", "ip_addresses": []
                })
    for vnic_conf in vnic_configs_from_devices:
        networks.append(vnic_conf)

    primary_ip = vm_data.get("guest.ipAddress")
    if primary_ip and primary_ip not in all_ip_addresses: all_ip_addresses.append(primary_ip)
    unique_ip_addresses = sorted(list(set(ip for ip in all_ip_addresses if ip)))

    disks = []
    provisioned_storage_gb = 0.0
    for device in vm_devices:
        if isinstance(device, vim.vm.device.VirtualDisk):
            capacity_kb = getattr(device, 'capacityInKB', 0)
            if not capacity_kb and hasattr(device, 'capacityInBytes'):
                capacity_kb = getattr(device, 'capacityInBytes', 0) / 1024
            disk_capacity_gb = round(capacity_kb / (1024 * 1024), 2) if capacity_kb else 0.0
            provisioned_storage_gb += disk_capacity_gb
            disks.append({
                "label": device.deviceInfo.label, "capacity_gb": disk_capacity_gb,
                "thin_provisioned": getattr(device.backing, 'thinProvisioned', None),
                "disk_mode": getattr(device.backing, 'diskMode', None),
                "path": getattr(device.backing, 'fileName', "N/A"),
                "datastore_mor": str(getattr(device.backing, 'datastore', None))
            })

    vm_summary = {
        "name": vm_data.get("name", "N/A"),
        "instance_uuid": vm_data.get("config.instanceUuid", "N/A"),
        "bios_uuid": vm_data.get("config.uuid", "N/A"),
        "datacenter_name": DATACENTER_NAME, "cluster_name": cluster_name, "host_name": host_name,
        "guest_os": vm_data.get("summary.config.guestFullName", "N/A"),
        "guest_hostname": vm_data.get("guest.hostName", "N/A (Tools dependent)"),
        "ip_addresses_summary": unique_ip_addresses,
        "network_interfaces": networks,
        "power_state": str(vm_data.get("runtime.powerState", "N/A")),
        "vmware_tools_status": str(vm_data.get("guest.toolsStatus", "N/A")),
        "vmware_tools_version": vm_data.get("guest.toolsVersion", "N/A"),
        "cpu_sockets": num_cpu, "cores_per_socket": cores_per_socket, "total_cores": total_cores,
        "memory_gb": round(vm_data.get("config.hardware.memoryMB", 0) / 1024, 2),
        "vm_path": vm_data.get("summary.config.vmPathName", "N/A"),
        "annotation": vm_data.get("config.annotation", ""),
        "vm_hardware_version": vm_data.get("config.version", "N/A"),
        "creation_date": str(vm_data.get("config.createDate", "N/A")),
        "storage_summary": {
            "committed_gb": round(vm_data.get("summary.storage.committed", 0) / (1024 ** 3), 2),
            "uncommitted_gb": round(vm_data.get("summary.storage.uncommitted", 0) / (1024 ** 3), 2),
            "total_provisioned_gb_from_disks": round(provisioned_storage_gb, 2),
            "timestamp": str(vm_data.get("summary.storage.timestamp", "N/A"))
        },
        "disks": disks,
        "datastores_mor": [str(ds) for ds in vm_data.get("datastore", [])],
        "resource_pool_mor": str(vm_data.get("resourcePool", "N/A"))
    }
    return vm_summary


# --- Main execution ---
if __name__ == "__main__":
    logger.info("Starting optimized vCenter inventory collection...")
    full_results = []

    current_vc_password = VC_PASSWORD_ENV  # Password from .env
    prompted_for_password = False
    if not current_vc_password:
        try:
            current_vc_password = getpass.getpass(
                prompt=f"Enter password for VMware user '{VC_USER}' (for all listed vCenters): "
            )
            prompted_for_password = True
        except Exception as e:
            logger.error(f"Could not read password: {e}")
            exit(1)

    try:
        with ThreadPoolExecutor(max_workers=min(5, len(VC_HOSTS) if VC_HOSTS else 1)) as executor:
            future_to_vc = {
                executor.submit(collect_inventory_from_vcenter, vc_host, VC_USER, current_vc_password, VC_PORT,
                                DISABLE_SSL_VERIFICATION): vc_host
                for vc_host in VC_HOSTS
            }
            for future in as_completed(future_to_vc):
                vc_host = future_to_vc[future]
                try:
                    result = future.result()
                    if result:
                        full_results.append(result)
                except Exception as exc:
                    logger.error(f"vCenter {vc_host} generated an exception during future.result(): {exc}",
                                 exc_info=True)
    except Exception as e_main_pool:
        logger.error(f"Error during ThreadPoolExecutor execution: {e_main_pool}", exc_info=True)
    finally:
        if prompted_for_password and 'current_vc_password' in locals():
            del current_vc_password

    if full_results:
        # Dynamic output filename
        output_file_name = f"vmware_inventory_{DATACENTER_NAME}.json"
        output_file_path = Path(__file__).resolve().parent / output_file_name

        try:
            with open(output_file_path, "w") as f:
                json.dump(full_results, f, indent=4, default=str)
            logger.info(f"✅ Inventory saved to {output_file_path}")
        except Exception as e:
            logger.error(f"Failed to save inventory to JSON: {e}", exc_info=True)
    else:
        logger.warning("❌ No inventory collected from any vCenter or all tasks failed.")

    logger.info("Script finished.")
