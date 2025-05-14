#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["python-dotenv", "openstacksdk"]
# ///

import os
import json
import logging
import re  # For sanitizing filename
from dotenv import load_dotenv
import openstack
from pathlib import Path

# --- Load Config ---
load_dotenv(Path(__file__).resolve().parent / ".env")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')
logger = logging.getLogger(__name__)

OS_INSECURE_ENV = os.getenv('OS_INSECURE', 'false').lower()
DATACENTER_NAME_env = os.getenv('DATACENTER_NAME', 'DefaultCloud')
# Sanitize DATACENTER_NAME for use in filename
DATACENTER_NAME = re.sub(r'[^\w_.)( -]', '', DATACENTER_NAME_env)
if not DATACENTER_NAME: DATACENTER_NAME = "DefaultCloud"

# Dynamic output filename
OUTPUT_FILENAME = f"openstack_inventory_{DATACENTER_NAME}.json"
INSTANCE_SAVE_BATCH_SIZE = 50  # Reduced for more frequent saves during instance processing
REQUESTS_TIMEOUT = 30

if OS_INSECURE_ENV == 'true':
    logger.warning(
        "SSL CERTIFICATE VERIFICATION IS DISABLED for OpenStack connections via OS_INSECURE. This is a security risk.")


# --- Helpers ---
def save_inventory_to_json(data, filename):
    try:
        # Ensure the parent directory exists if filename includes path elements
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        logger.info(f"Inventory data saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save inventory to {filename}: {e}")


# --- Connection ---
def connect_to_openstack():
    try:
        # openstacksdk.enable_logging(debug=True) # Uncomment for verbose SDK logging
        conn = openstack.connect(timeout=REQUESTS_TIMEOUT)
        specified_region = os.getenv('OS_REGION_NAME', "N/A (OS_REGION_NAME not set)")
        logger.info(f"Attempting to use OpenStack services in region: {specified_region} "
                    f"(User: {os.getenv('OS_USERNAME')}, Project: {os.getenv('OS_PROJECT_NAME')})")
        try:
            if conn.identity:
                conn.identity.endpoints()
                logger.info(
                    f"Successfully established session with OpenStack Identity service in region: {specified_region}.")
            else:
                logger.warning(
                    f"Identity service client not available on connection object for region: {specified_region}.")
        except Exception as e_session_check:
            logger.error(
                f"Failed to confirm session with OpenStack Identity service in region {specified_region}: {e_session_check}")
            return None
        return conn
    except openstack.exceptions.SDKException as e:
        logger.error(f"Failed to connect to OpenStack (SDKException): {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred during OpenStack connection: {e}", exc_info=True)
    return None


# --- Data Fetch Functions ---
def get_all_projects(conn):
    projects_info = []
    logger.info("Fetching all projects...")
    try:
        if not conn.identity:
            logger.error("Identity service not available. Cannot fetch projects.")
            return projects_info
        projects = conn.identity.projects()
        for p in projects:
            projects_info.append({
                "id": p.id, "name": p.name, "description": p.description,
                "enabled": p.is_enabled, "domain_id": p.domain_id,
                "parent_id": getattr(p, 'parent_id', None),
                "datacenter": DATACENTER_NAME  # Consistent with VMware output structure
            })
        logger.info(f"Successfully fetched {len(projects_info)} projects.")
    except Exception as e:
        logger.error(f"Error fetching projects: {e}", exc_info=True)
    return projects_info


def get_availability_zones(conn):
    zones_info = []
    logger.info("Fetching availability zones...")
    try:
        if not conn.compute:
            logger.error("Compute service not available. Cannot fetch AZs.")
            return zones_info
        # Use list() to ensure all items are fetched if it's a generator
        zones = list(conn.compute.availability_zones(details=True))  # details=True is important
        for z in zones:
            # Accessing state safely based on common SDK patterns
            is_available = True  # Default to True if state info is missing
            if hasattr(z, 'zone_state') and z.zone_state and hasattr(z.zone_state, 'available'):
                is_available = z.zone_state.available
            elif hasattr(z, 'state') and isinstance(z.state, dict):  # From user's previous VMware logs
                is_available = z.state.get('available', True)
            elif hasattr(z, 'is_available'):  # Simpler boolean if present
                is_available = z.is_available

            hosts_in_zone = []
            if hasattr(z, 'hosts') and z.hosts and isinstance(z.hosts, dict):
                hosts_in_zone = list(z.hosts.keys())

            zones_info.append({
                "name": z.name,
                "available": is_available,
                "host_count": len(hosts_in_zone),
                "hosts": hosts_in_zone,  # List of hostnames in this AZ
                "datacenter": DATACENTER_NAME
            })
        logger.info(f"Fetched {len(zones_info)} availability zones.")
    except Exception as e:
        logger.error(f"Error fetching availability zones: {e}", exc_info=True)
    return zones_info


def get_host_aggregates(conn):
    aggregates_info = []
    logger.info("Fetching host aggregates...")
    try:
        if not conn.compute:
            logger.error("Compute service not available. Cannot fetch host aggregates.")
            return aggregates_info
        aggregates = list(conn.compute.aggregates())
        for a in aggregates:
            aggregates_info.append({
                "id": a.id, "name": a.name,
                "availability_zone": a.availability_zone,
                "host_count": len(a.hosts or []),
                "hosts": a.hosts or [],
                "metadata": a.metadata or {},
                "datacenter": DATACENTER_NAME
            })
        logger.info(f"Fetched {len(aggregates_info)} host aggregates.")
    except openstack.exceptions.ForbiddenException:
        logger.warning("Could not fetch host aggregates: Insufficient permissions.")
    except Exception as e:
        logger.error(f"Error fetching host aggregates: {e}", exc_info=True)
    return aggregates_info


def get_hypervisors(conn):
    hypervisors_info = []
    logger.info("Fetching hypervisor details...")
    try:
        # Using direct session.get as per user's working script for hypervisors
        # This assumes the endpoint is correct and returns the expected structure.
        # It might bypass some SDK object normalization.
        if not (conn.session and conn.compute):
            logger.error("Session or Compute service endpoint not available for fetching hypervisors.")
            return []

        compute_endpoint = conn.compute.get_endpoint()
        if not compute_endpoint:
            logger.error("Could not determine compute endpoint for hypervisors.")
            return []

        # The direct API call often includes more details than the SDK object if not all mapped
        # Ensure the user has admin rights for os-hypervisors/detail
        resp = conn.session.get(
            compute_endpoint.rstrip('/') + '/os-hypervisors/detail',
            endpoint_filter={'service_type': 'compute', 'interface': conn.compute.default_interface}
        )
        resp.raise_for_status()  # Will raise an exception for HTTP error codes

        raw_hypervisors = resp.json().get('hypervisors', [])
        logger.info(f"Retrieved {len(raw_hypervisors)} hypervisor entries from API.")

        for i, hv_dict in enumerate(raw_hypervisors):
            if i == 0 and logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"Raw data for first hypervisor: {hv_dict}")

            # hv.name in your script was hypervisor_hostname, let's stick to that if it's the FQDN
            name_from_api = hv_dict.get('hypervisor_hostname', hv_dict.get('name', 'N/A'))

            # For CPU info, it's often a string or a complex object.
            # We will store it as is or try to summarize if it's too verbose.
            cpu_info_raw = hv_dict.get('cpu_info', 'N/A')
            cpu_info_processed = cpu_info_raw
            if isinstance(cpu_info_raw, str):
                try:  # Try to parse if it's JSON string
                    parsed_cpu_info = json.loads(cpu_info_raw)
                    # Extract key details if possible, otherwise keep parsed or raw
                    cpu_info_processed = {
                        "topology": parsed_cpu_info.get("topology"),
                        "features": parsed_cpu_info.get("features"),
                        "model": parsed_cpu_info.get("model")
                    }
                except json.JSONDecodeError:
                    # If not JSON, keep as string but maybe truncate if very long
                    cpu_info_processed = cpu_info_raw[:255] + "..." if len(cpu_info_raw) > 255 else cpu_info_raw
            elif isinstance(cpu_info_raw, dict):  # If already a dict
                cpu_info_processed = {
                    "topology": cpu_info_raw.get("topology"),
                    "features": cpu_info_raw.get("features"),
                    "model": cpu_info_raw.get("model")
                }

            hypervisor_detail = {
                "id": hv_dict.get('id'),
                "name": name_from_api,  # Using the potentially FQDN
                "hypervisor_hostname": name_from_api,  # Consistent with 'name' from API if it's FQDN
                "state": hv_dict.get('state', 'N/A'),
                "status": hv_dict.get('status', 'N/A'),
                "type": hv_dict.get('hypervisor_type', 'N/A'),
                "version": hv_dict.get('hypervisor_version'),  # Version can be int or string
                "vcpus_total": hv_dict.get('vcpus'),
                "vcpus_used": hv_dict.get('vcpus_used'),
                "memory_total_mb": hv_dict.get('memory_mb'),
                "memory_used_mb": hv_dict.get('memory_mb_used'),
                "local_storage_total_gb": hv_dict.get('local_gb'),
                "local_storage_used_gb": hv_dict.get('local_gb_used'),
                "running_vms": hv_dict.get('running_vms'),
                "service_id": hv_dict.get('service', {}).get('id'),
                "service_host": hv_dict.get('service', {}).get('host', 'N/A'),
                "host_ip": hv_dict.get('host_ip', 'N/A'),
                "cpu_info": cpu_info_processed,
                "disk_available_least_gb": hv_dict.get('disk_available_least'),  # Often in GB
                "free_disk_gb": hv_dict.get('free_disk_gb'),
                "free_ram_mb": hv_dict.get('free_ram_mb'),
                "uptime": hv_dict.get('uptime', 'N/A'),  # Often a string like "10 days, 2:34:56"
                "current_workload": hv_dict.get('current_workload', None),
                # Fields like vendor, model, serial are not standard in os-hypervisors API
                "vendor": "N/A (Not typically available via OpenStack Hypervisor API)",
                "model": "N/A (Not typically available via OpenStack Hypervisor API)",
                "serial_number": "N/A (Not typically available via OpenStack Hypervisor API)",
                "datacenter": DATACENTER_NAME
            }
            hypervisors_info.append(hypervisor_detail)
        logger.info(f"Processed {len(hypervisors_info)} hypervisors.")
    except openstack.exceptions.ForbiddenException:
        logger.warning(
            "Could not fetch hypervisor details: Insufficient permissions (admin required for /os-hypervisors/detail).")
    except openstack.exceptions.HttpException as e:
        logger.error(f"HTTP error fetching hypervisors: {e.response.status_code} - {e.response.text}")
    except Exception as e:
        logger.error(f"Error fetching hypervisors: {e}", exc_info=True)
    return hypervisors_info


def get_flavor_details(conn, flavor_ref):
    """Helper to fetch full flavor details, returning a structured dict or basic info on failure."""
    if not flavor_ref or not flavor_ref.get('id'):
        return {"id": "N/A", "name": "N/A (No reference)", "vcpus": None, "ram_mb": None, "disk_gb": None,
                "ephemeral_gb": None, "swap_mb": None}

    flavor_id = flavor_ref.get('id')
    flavor_name_from_server = flavor_ref.get('original_name',
                                             flavor_ref.get('name', 'N/A'))  # Server object might have 'original_name'

    try:
        if not conn.compute:
            logger.warning(f"Compute service not available. Cannot fetch details for flavor ID {flavor_id}")
            return {"id": flavor_id, "name": flavor_name_from_server + " (Compute service unavailable)", "vcpus": None,
                    "ram_mb": None, "disk_gb": None}

        flavor = conn.compute.get_flavor(flavor_id)  # get_flavor expects ID
        return {
            "id": flavor.id,
            "name": flavor.name,
            "vcpus": flavor.vcpus,
            "ram_mb": flavor.ram,
            "disk_gb": flavor.disk,  # Root disk
            "ephemeral_gb": getattr(flavor, 'ephemeral_disk_size', getattr(flavor, 'OS-FLV-EXT-DATA:ephemeral', 0)),
            "swap_mb": getattr(flavor, 'swap_disk_size', (flavor.swap if isinstance(flavor.swap, (int, float)) else 0)),
            "is_public": getattr(flavor, 'is_public', True),
            "extra_specs": getattr(flavor, 'extra_specs', {})
        }
    except openstack.exceptions.ResourceNotFound:
        logger.warning(
            f"Flavor ID '{flavor_id}' (name hint: '{flavor_name_from_server}') not found during detailed fetch.")
        return {"id": flavor_id, "name": flavor_name_from_server + " (Not Found)", "vcpus": None, "ram_mb": None,
                "disk_gb": None}
    except Exception as e:
        logger.warning(
            f"Could not fetch full details for flavor ID '{flavor_id}' (name hint: '{flavor_name_from_server}'): {e}")
        return {"id": flavor_id, "name": flavor_name_from_server + " (Error fetching details)", "vcpus": None,
                "ram_mb": None, "disk_gb": None}


def get_instances(conn, project_map, inventory, flavor_map_unused):  # flavor_map_unused as we fetch per instance
    # (This function was provided by the user, adapting it for more details)
    instance_details_list = inventory.get("instances", [])  # Resume if possible
    processed_server_ids = {inst["id"] for inst in instance_details_list}
    newly_processed_count = 0

    logger.info("Fetching instances (servers)...")
    try:
        if not conn.compute:
            logger.error("Compute service not available. Cannot fetch instances.")
            return instance_details_list

        # Fetch all servers with details
        all_servers = list(conn.compute.servers(details=True, all_projects=True))
        total_servers_to_process = len(all_servers)
        logger.info(f"Found {total_servers_to_process} total server objects to process/update.")

        for idx, s in enumerate(all_servers):
            if s.id in processed_server_ids:
                logger.debug(f"Skipping already processed instance {s.name} (ID: {s.id})")
                continue

            logger.info(f"[{idx + 1}/{total_servers_to_process}] Processing instance: {s.name} (ID: {s.id})")

            # Flavor details - now calling helper
            flavor_info = get_flavor_details(conn, s.flavor)

            # Basic Image Info (detailed fetch is skipped as per user request)
            image_info = {
                "id": s.image.get('id') if s.image else "N/A",
                "name": s.image.get('name', "N/A (Details not fetched)") if s.image else "N/A (No image ref)"
            }
            if s.image and s.image.get('id') and logging.getLogger().getEffectiveLevel() == logging.DEBUG:
                logger.debug(f"Instance {s.name}: Basic image ref ID: {s.image.get('id')}, Name: {s.image.get('name')}")

            # Attached Volumes - enhanced
            attached_volumes_details = []
            if s.attached_volumes:
                logger.debug(f"Instance {s.name}: Fetching details for {len(s.attached_volumes)} attached volumes...")
                for vol_attachment in s.attached_volumes:
                    vol_id = vol_attachment.get('id')
                    if not vol_id: continue
                    try:
                        if not conn.volume:
                            logger.warning(
                                f"Volume service client not available. Cannot fetch volume {vol_id} for server {s.name}")
                            attached_volumes_details.append(
                                {"id": vol_id, "error": "Volume service client unavailable"})
                            continue

                        volume = conn.volume.get_volume(vol_id)
                        attached_volumes_details.append({
                            "id": volume.id,
                            "name": volume.name,
                            "size_gb": volume.size,
                            "status": volume.status,
                            "type": volume.volume_type if volume.volume_type else "N/A",
                            "bootable": str(volume.is_bootable).lower(),  # Match True/False string like VMware
                            "device": vol_attachment.get('device', 'N/A'),
                            "created_at": volume.created_at,
                            "multiattach": getattr(volume, 'is_multiattach', False),
                            "metadata": volume.metadata or {}
                        })
                    except openstack.exceptions.SDKException as e:
                        logger.warning(f"Could not fetch details for volume {vol_id} on server {s.name}: {e}")
                        attached_volumes_details.append({"id": vol_id, "error": "Failed to fetch details"})

            # IP Addresses and Networks
            ip_addresses_list = []
            networks_list = []
            if s.addresses:
                for network_name, addresses_on_net in s.addresses.items():
                    current_network_ips = []
                    for addr_info in addresses_on_net:
                        ip_detail = {
                            "ip": addr_info.get("addr"),
                            "type": addr_info.get("OS-EXT-IPS:type", "unknown"),
                            "mac_addr": addr_info.get("OS-EXT-IPS-MAC:mac_addr", "N/A"),
                            "version": addr_info.get("version", 4)
                        }
                        ip_addresses_list.append(ip_detail)
                        current_network_ips.append(ip_detail["ip"])
                    networks_list.append({"name": network_name, "ips_on_network": current_network_ips})

            instance_data = {
                "id": s.id,
                "name": s.name,
                "status": s.status,
                "power_state": getattr(s, 'power_state', 'N/A'),  # Map to VMware's power_state
                "task_state": getattr(s, 'task_state', 'N/A'),
                "vm_state": getattr(s, 'vm_state', 'N/A'),  # More detailed OpenStack state
                "created_at": s.created_at,
                "updated_at": s.updated_at,
                "launched_at": getattr(s, 'launched_at', 'N/A'),
                "terminated_at": getattr(s, 'terminated_at', 'N/A'),
                "project_id": s.project_id,
                "project_name": project_map.get(s.project_id, "N/A"),
                "user_id": s.user_id,
                "hypervisor_hostname": getattr(s, 'hypervisor_hostname', getattr(s, 'host_id', 'N/A')),
                "availability_zone": getattr(s, 'availability_zone', 'N/A'),
                "key_name": s.key_name or 'N/A',
                "flavor": flavor_info,
                "image": image_info,
                "attached_volumes": attached_volumes_details,
                "ip_addresses_detailed": ip_addresses_list,  # Renamed from ip_addresses for clarity
                "networks_summary": networks_list,  # Renamed from networks for clarity
                "security_groups": [sg['name'] for sg in s.security_groups] if s.security_groups else [],
                "metadata": s.metadata or {},
                "config_drive": str(s.config_drive).lower() if hasattr(s, 'config_drive') else "unknown",
                "addresses_raw": s.addresses,  # Include the raw addresses structure for reference
                "datacenter": DATACENTER_NAME  # For consistency
            }
            instance_details_list.append(instance_data)
            processed_server_ids.add(s.id)
            newly_processed_count += 1

            if newly_processed_count > 0 and newly_processed_count % INSTANCE_SAVE_BATCH_SIZE == 0:
                logger.info(
                    f"Saving intermediate instance data (processed {newly_processed_count} new, total: {len(instance_details_list)})...")
                inventory["instances"] = instance_details_list  # Update the main object being built
                save_inventory_to_json(inventory, Path(Path(__file__).resolve().parent, OUTPUT_FILENAME))

        logger.info(f"Finished processing {total_servers_to_process} server objects.")

    except openstack.exceptions.ForbiddenException:
        logger.warning("Could not list instances: Insufficient permissions (admin required for all_projects=True).")
    except Exception as e:
        logger.error(f"Error fetching instances: {e}", exc_info=True)
    return instance_details_list


# --- Main ---
if __name__ == "__main__":
    logger.info("Starting OpenStack inventory collection...")

    output_file_path = Path(Path(__file__).resolve().parent, OUTPUT_FILENAME)

    conn = connect_to_openstack()
    if not conn:
        logger.error("Exiting due to connection failure.")
        exit(1)

    inventory = {}
    if os.path.exists(output_file_path):
        try:
            with open(output_file_path, "r") as f:
                inventory = json.load(f)
            logger.info(f"Loaded existing inventory from {output_file_path}")
        except Exception as e:
            logger.warning(f"Could not load existing inventory from {output_file_path}: {e}. Starting fresh.")
            inventory = {}

    # Ensure base structure exists
    inventory.setdefault("datacenter", DATACENTER_NAME)  # Add top-level datacenter/region name
    inventory.setdefault("projects_list", [])
    inventory.setdefault("availability_zones", [])
    inventory.setdefault("host_aggregates", [])
    inventory.setdefault("hypervisors", [])
    inventory.setdefault("instances", [])

    try:
        if not inventory["projects_list"]:
            inventory["projects_list"] = get_all_projects(conn)
            save_inventory_to_json(inventory, output_file_path)
        project_map = {p["id"]: p["name"] for p in inventory["projects_list"]}

        if not inventory["availability_zones"]:
            inventory["availability_zones"] = get_availability_zones(conn)
            save_inventory_to_json(inventory, output_file_path)

        if not inventory["host_aggregates"]:
            inventory["host_aggregates"] = get_host_aggregates(conn)
            save_inventory_to_json(inventory, output_file_path)

        if not inventory["hypervisors"]:
            inventory["hypervisors"] = get_hypervisors(conn)
            save_inventory_to_json(inventory, output_file_path)

        # flavor_map is not used by the modified get_instances, can be removed if not needed elsewhere
        # flavor_map = get_flavor_map(conn) # Original call, but get_instances now fetches flavor details per instance

        inventory["instances"] = get_instances(conn, project_map, inventory)  # Pass inventory for periodic save
        save_inventory_to_json(inventory, output_file_path)  # Final save

    except KeyboardInterrupt:
        logger.warning("Script execution interrupted by user. Saving partial data.")
        save_inventory_to_json(inventory, output_file_path)
    except Exception as e_main:
        logger.error(f"A critical error occurred in main execution: {e_main}", exc_info=True)
        save_inventory_to_json(inventory, output_file_path)  # Attempt to save on other errors
    finally:
        if conn:
            try:
                conn.close()
                logger.info("Closed connection to OpenStack.")
            except Exception as e_close:
                logger.warning(f"Error closing OpenStack connection: {e_close}")

    logger.info(f"✅ OpenStack inventory collection complete. Data saved to {output_file_path}")
