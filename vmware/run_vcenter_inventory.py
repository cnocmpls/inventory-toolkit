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
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
from pyVim import connect
from pyVmomi import vim, vmodl

# --- Config ---
load_dotenv(Path(__file__).resolve().parent / ".env")
DATACENTER_NAME = os.getenv("DATACENTER_NAME", "N/A")
VC_USER = os.getenv("VCENTER_USER")
VC_PASSWORD = os.getenv("VCENTER_PASSWORD")
VC_HOSTS = [h.strip() for h in os.getenv("VCENTER_HOSTS", "").split(",") if h.strip()]
VC_PORT = int(os.getenv("VCENTER_PORT", 443))

DISABLE_SSL_VERIFICATION = True
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- Utility: fast property collector ---
def collect_properties(si, obj_type, properties):
    content = si.RetrieveContent()
    container = content.viewManager.CreateContainerView(content.rootFolder, [obj_type], True)

    obj_spec = vmodl.query.PropertyCollector.ObjectSpec(obj=container, skip=True)
    traversal = vmodl.query.PropertyCollector.TraversalSpec(name="traverseEntities", path="view", skip=False, type=container.__class__)
    obj_spec.selectSet = [traversal]

    prop_spec = vmodl.query.PropertyCollector.PropertySpec(type=obj_type, all=False, pathSet=properties)
    filter_spec = vmodl.query.PropertyCollector.FilterSpec(objectSet=[obj_spec], propSet=[prop_spec])

    results = []
    props = content.propertyCollector.RetrievePropertiesEx([filter_spec], vmodl.query.PropertyCollector.RetrieveOptions())

    while props:
        for o in props.objects:
            result = {"obj": o.obj}
            for p in o.propSet:
                result[p.name] = p.val
            results.append(result)

        token = props.token
        if token:
            props = content.propertyCollector.ContinueRetrievePropertiesEx(token)
        else:
            break

    container.Destroy()
    return results

# --- vCenter connect ---
def connect_to_vcenter(host):
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE
    try:
        si = connect.SmartConnect(host=host, user=VC_USER, pwd=VC_PASSWORD, port=VC_PORT, sslContext=ssl_ctx)
        atexit.register(connect.Disconnect, si)
        logger.info(f"Connected to vCenter: {host}")
        return si
    except Exception as e:
        logger.error(f"Failed to connect to {host}: {e}")
        return None

# --- Inventory logic ---
def collect_inventory_from_host(host):
    si = connect_to_vcenter(host)
    if not si:
        return None

    content = si.RetrieveContent()

    clusters = collect_properties(si, vim.ClusterComputeResource, ["name", "host", "configuration.dasConfig.enabled", "configuration.drsConfig.defaultVmBehavior"])
    hosts = collect_properties(si, vim.HostSystem, ["name", "config.product.fullName", "summary.hardware.numCpuCores", "summary.hardware.cpuMhz", "summary.hardware.memorySize", "runtime.connectionState"])
    vms = collect_properties(si, vim.VirtualMachine, ["name", "summary.config.guestFullName", "guest.hostName", "guest.ipAddress", "runtime.powerState", "guest.toolsStatus", "config.hardware.numCPU", "config.hardware.numCoresPerSocket", "config.hardware.memoryMB", "summary.storage.committed", "summary.storage.uncommitted", "runtime.host", "summary.config.vmPathName"])

    host_map = {h["obj"]: h for h in hosts}
    vm_map = {v["obj"]: v for v in vms}

    # Map host → [vm, vm]
    host_to_vms = {}
    for vm_data in vms:
        host_ref = vm_data.get("runtime.host")
        if host_ref:
            host_to_vms.setdefault(host_ref, []).append(vm_data)

    inventory = {
        "vcenter": host,
        "datacenter": DATACENTER_NAME,
        "clusters": [],
        "standalone_hosts": []
    }

    clustered_hosts = set()
    for cluster in clusters:
        cluster_info = {
            "name": cluster.get("name", "N/A"),
            "datacenter": DATACENTER_NAME,
            "drs_status": str(cluster.get("configuration.drsConfig.defaultVmBehavior", "N/A")),
            "ha_status": cluster.get("configuration.dasConfig.enabled", False),
            "total_hosts": len(cluster.get("host", [])),
            "hosts": []
        }

        for host_ref in cluster.get("host", []):
            clustered_hosts.add(host_ref)
            host_info = host_map.get(host_ref)
            if not host_info:
                continue
            cluster_info["hosts"].append(process_host_and_vms(host_info, host_to_vms.get(host_ref, [])))
        inventory["clusters"].append(cluster_info)

    for host_ref, host_info in host_map.items():
        if host_ref not in clustered_hosts:
            inventory["standalone_hosts"].append(process_host_and_vms(host_info, host_to_vms.get(host_ref, [])))

    connect.Disconnect(si)
    return inventory

def process_host_and_vms(host_info, vms_for_host):
    host_summary = {
        "name": host_info.get("name", "N/A"),
        "esxi_version": host_info.get("config.product.fullName", "N/A"),
        "cpu_cores": host_info.get("summary.hardware.numCpuCores"),
        "cpu_mhz_per_core": host_info.get("summary.hardware.cpuMhz"),
        "total_memory_gb": round(host_info.get("summary.hardware.memorySize", 0) / (1024**3), 2),
        "connection_state": str(host_info.get("runtime.connectionState", "N/A")),
        "datacenter": DATACENTER_NAME,
        "vms": []
    }

    for vm_data in vms_for_host:
        total_cores = "N/A"
        try:
            cpu = vm_data.get("config.hardware.numCPU", 0)
            cores = vm_data.get("config.hardware.numCoresPerSocket", 1)
            total_cores = cpu * cores
        except Exception:
            pass

        vm_summary = {
            "name": vm_data.get("name", "N/A"),
            "datacenter": DATACENTER_NAME,
            "guest_os": vm_data.get("summary.config.guestFullName", "N/A"),
            "guest_hostname": vm_data.get("guest.hostName", "N/A"),
            "ip_addresses": [vm_data.get("guest.ipAddress")] if vm_data.get("guest.ipAddress") else [],
            "power_state": str(vm_data.get("runtime.powerState", "N/A")),
            "vmware_tools_status": str(vm_data.get("guest.toolsStatus", "N/A")),
            "cpu_sockets": vm_data.get("config.hardware.numCPU"),
            "cores_per_socket": vm_data.get("config.hardware.numCoresPerSocket"),
            "total_cores": total_cores,
            "memory_gb": round(vm_data.get("config.hardware.memoryMB", 0) / 1024, 2),
            "vm_path": vm_data.get("summary.config.vmPathName", "N/A"),
            "storage": {
                "committed_gb": round(vm_data.get("summary.storage.committed", 0) / (1024**3), 2),
                "uncommitted_gb": round(vm_data.get("summary.storage.uncommitted", 0) / (1024**3), 2)
            }
        }
        host_summary["vms"].append(vm_summary)

    return host_summary

# --- Main execution ---
if __name__ == "__main__":
    logger.info("Starting optimized vCenter inventory collection...")

    results = []
    with ThreadPoolExecutor(max_workers=min(5, len(VC_HOSTS))) as executor:
        future_map = {executor.submit(collect_inventory_from_host, vc): vc for vc in VC_HOSTS}
        for future in as_completed(future_map):
            result = future.result()
            if result:
                results.append(result)

    if results:
        with open("vcenter_inventory_env_no_ssl.json", "w") as f:
            json.dump(results, f, indent=4, default=str)
        logger.info("✅ Inventory saved to vcenter_inventory_env_no_ssl.json")
    else:
        logger.warning("❌ No inventory collected.")
