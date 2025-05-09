# 1. Install uv (if not present)
curl -LsSf https://astral.sh/uv/install.sh | sh

echo 'eval "$(uv generate-shell-completion bash)"' >> ~/.bashrc
echo 'eval "$(uvx --generate-shell-completion bash)"' >> ~/.bashrc
uv python install

#2. Make it executable:
chmod +x ./vmware/run_vcenter_inventory.py
chmod +x ./openstack/run_openstack_inventory.py

# 2. Run the script
./openstack/run_openstack_inventory.py
# or
./vmware/run_vcenter_inventory.py