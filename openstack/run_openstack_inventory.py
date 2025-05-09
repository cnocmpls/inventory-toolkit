#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# dependencies = ["python-dotenv", "openstacksdk"]
# ///

import os
import json
import logging
from dotenv import load_dotenv
import openstack
from pathlib import Path

# --- Load Config ---
load_dotenv(Path(__file__).resolve().parent / ".env")

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

OS_INSECURE_ENV = os.getenv('OS_INSECURE', 'false').lower()
DATACENTER_NAME = os.getenv('DATACENTER_NAME', 'N/A')
OUTPUT_FILENAME = "openstack_inventory_all_projects.json"
INSTANCE_SAVE_BATCH_SIZE = 100
REQUESTS_TIMEOUT = 30

if OS_INSECURE_ENV == 'true':
    logger.warning("SSL CERTIFICATE VERIFICATION IS DISABLED for OpenStack connections via OS_INSECURE. This is a security risk.")

# --- Helpers ---
def save_inventory_to_json(data, filename):
    try:
        with open(filename, "w") as f:
            json.dump(data, f, indent=4, default=str)
        logger.info(f"Inventory data saved to {filename}")
    except Exception as e:
        logger.error(f"Failed to save inventory: {e}")

# --- Connection ---
def connect_to_openstack():
    try:
        conn = openstack.connect(timeout=REQUESTS_TIMEOUT)
        conn.identity.endpoints()
        logger.info("Connected to OpenStack Identity service.")
        return conn
    except Exception as e:
        logger.error(f"Failed to connect to OpenStack: {e}", exc_info=True)
        return None

# --- Data Fetch Functions ---
def get_all_projects(conn):
    try:
        return [{
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "enabled": p.is_enabled,
            "domain_id": p.domain_id,
            "parent_id": getattr(p, 'parent_id', None),
            "datacenter": DATACENTER_NAME
        } for p in conn.identity.projects()]
    except Exception as e:
        logger.error(f"Error fetching projects: {e}")
        return []

def get_availability_zones(conn):
    try:
        return [{
            "name": z.name,
            "available": getattr(z, 'available', True),
            "hosts": list(z.hosts.keys()) if hasattr(z, 'hosts') and isinstance(z.hosts, dict) else [],
            "datacenter": DATACENTER_NAME
        } for z in conn.compute.availability_zones()]
    except Exception as e:
        logger.error(f"Error fetching availability zones: {e}")
        return []

def get_host_aggregates(conn):
    try:
        return [{
            "id": a.id,
            "name": a.name,
            "availability_zone": a.availability_zone,
            "hosts": a.hosts,
            "metadata": a.metadata,
            "datacenter": DATACENTER_NAME
        } for a in conn.compute.aggregates()]
    except Exception as e:
        logger.error(f"Error fetching host aggregates: {e}")
        return []

def get_hypervisors(conn):
    try:
        session = conn.session
        compute_url = conn.compute.get_endpoint()
        resp = session.get(compute_url.rstrip('/') + '/os-hypervisors/detail',
                           endpoint_filter={'service_type': 'compute'})
        if resp.status_code != 200:
            logger.error(f"Failed to fetch hypervisor details: HTTP {resp.status_code}")
            return []
        return [{
            "id": hv.get('id'),
            "name": hv.get('hypervisor_hostname'),
            "hypervisor_hostname": hv.get('hypervisor_hostname', 'N/A'),
            "state": hv.get('state', 'N/A'),
            "status": hv.get('status', 'N/A'),
            "type": hv.get('hypervisor_type', 'N/A'),
            "version": hv.get('hypervisor_version', 'N/A'),
            "vcpus_total": hv.get('vcpus'),
            "vcpus_used": hv.get('vcpus_used'),
            "memory_total_mb": hv.get('memory_mb'),
            "memory_used_mb": hv.get('memory_mb_used'),
            "local_storage_total_gb": hv.get('local_gb'),
            "local_storage_used_gb": hv.get('local_gb_used'),
            "running_vms": hv.get('running_vms'),
            "service_host": hv.get('service', {}).get('host', 'N/A'),
            "host_ip": hv.get('host_ip', 'N/A'),
            "datacenter": DATACENTER_NAME
        } for hv in resp.json().get('hypervisors', [])]
    except Exception as e:
        logger.error(f"Error fetching hypervisors: {e}", exc_info=True)
        return []

def get_flavor_map(conn):
    try:
        return {f.name: f for f in conn.compute.flavors()}
    except Exception as e:
        logger.error(f"Error fetching flavors: {e}")
        return {}

def get_instances(conn, project_map, inventory, flavor_map):
    try:
        servers = list(conn.compute.servers(details=True, all_projects=True))
    except Exception as e:
        logger.error(f"Error fetching instances: {e}")
        return []

    results = []
    for idx, s in enumerate(servers):
        logger.info(f"[{idx+1}/{len(servers)}] Processing {s.name}")
        fid = s.flavor.get('id') if s.flavor else 'N/A'
        flavor = flavor_map.get(fid) or flavor_map.get(s.flavor.get('original_name', ''))
        instance = {
            "id": s.id,
            "name": s.name,
            "status": s.status,
            "created_at": s.created_at,
            "updated_at": s.updated_at,
            "project_id": s.project_id,
            "project_name": project_map.get(s.project_id, "N/A"),
            "user_id": s.user_id,
            "hypervisor_hostname": getattr(s, 'hypervisor_hostname', 'N/A'),
            "availability_zone": getattr(s, 'availability_zone', 'N/A'),
            "key_name": s.key_name or 'N/A',
            "flavor": {
                "id": fid,
                "name": flavor.name if flavor else "N/A",
                "vcpus": flavor.vcpus if flavor else None,
                "ram_mb": flavor.ram if flavor else None,
                "disk_gb": flavor.disk if flavor else None
            },
            "image": {
                "id": s.image.get('id') if s.image else "N/A",
                "name": s.image.get('name', 'N/A') if s.image else "N/A"
            },
            "attached_volumes": [],
            "ip_addresses": [],
            "networks": [],
            "security_groups": [sg['name'] for sg in s.security_groups] if s.security_groups else [],
            "datacenter": DATACENTER_NAME
        }

        for net, addresses in s.addresses.items():
            net_ips = []
            for addr in addresses:
                ip = {
                    "ip": addr.get("addr"),
                    "type": addr.get("OS-EXT-IPS:type", "unknown"),
                    "mac_addr": addr.get("OS-EXT-IPS-MAC:mac_addr", "N/A"),
                    "version": addr.get("version", 4)
                }
                instance["ip_addresses"].append(ip)
                net_ips.append(ip["ip"])
            instance["networks"].append({"name": net, "ips_on_network": net_ips})

        results.append(instance)

        if (idx + 1) % INSTANCE_SAVE_BATCH_SIZE == 0:
            inventory["instances"] = results
            save_inventory_to_json(inventory, OUTPUT_FILENAME)

    return results

# --- Main ---
if __name__ == "__main__":
    logger.info("Starting OpenStack inventory collection...")
    conn = connect_to_openstack()
    if not conn:
        exit(1)

    inventory = {}
    if os.path.exists(OUTPUT_FILENAME):
        try:
            with open(OUTPUT_FILENAME) as f:
                inventory = json.load(f)
        except Exception:
            inventory = {}

    inventory["projects_list"] = get_all_projects(conn)
    project_map = {p["id"]: p["name"] for p in inventory["projects_list"]}

    inventory["availability_zones"] = get_availability_zones(conn)
    inventory["host_aggregates"] = get_host_aggregates(conn)
    inventory["hypervisors"] = get_hypervisors(conn)
    flavor_map = get_flavor_map(conn)
    inventory["instances"] = get_instances(conn, project_map, inventory, flavor_map)

    save_inventory_to_json(inventory, OUTPUT_FILENAME)
    logger.info("✅ OpenStack inventory collection complete.")
