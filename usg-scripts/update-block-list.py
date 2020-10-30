from azure.storage.queue import QueueServiceClient, QueueClient, QueueMessage
import os, uuid, base64, json, requests, sys


def main():
    connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    username = os.getenv("UNIFI_USERNAME")
    password = os.getenv("UNIFI_PASSWORD")
    unifi_controller = os.getenv("UNIFI_CONTROLLER")
    updater = FirewallUpdater(unifi_controller, username, password)
    queue_name = "threatsignals"

    queue_client = QueueClient.from_connection_string(connect_str, queue_name)
    messages = queue_client.receive_messages()
    for msg in messages:
        decoded = base64.b64decode(msg.content)
        reported_ip = json.loads(decoded)
        malicious_reports = reported_ip["malicious"]
        if malicious_reports > 0:
            ip = reported_ip["ip"]
            print(
                f"IP {ip} is reported as malicious by {malicious_reports} sources - adding to blocklist"
            )
            updater.add_ip_to_group("Block IPs", ip)

        queue_client.delete_message(msg)


class FirewallUpdater:
    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self._req = requests.Session()
        self._login(username, password)
        self._bad_ip_group = None

    def _login(self, username: str, password: str):
        self._req.post(
            f"https://{self.url}:8443/api/login",
            f'{{"username": "{username}", "password":"{password}"}}',
        )

    def _get_firewall_groups(self) -> dict:
        endpoint = f"https://{self.url}:8443/api/s/default/rest/firewallgroup"
        data = self._req.get(endpoint).json()
        return data["data"]

    def add_ip_to_group(self, group_name: str, ip_addr: str):
        if not self._bad_ip_group:
            groups = self._get_firewall_groups()
            bad_ip_group = [g for g in groups if g["name"] == "Block IPs"]
            if len(bad_ip_group) == 0:
                print("Did not find firewall group")
                sys.exit(1)

            bad_ip_group = bad_ip_group[0]
            self._bad_ip_group = bad_ip_group

        ips = self._bad_ip_group["group_members"]
        if ip_addr in ips:
            print(f"- {ip_addr} already registered")
            return

        ips.append(ip_addr)
        self._bad_ip_group["group_members"] = ips
        group_id = self._bad_ip_group["_id"]
        endpoint = (
            f"https://{self.url}:8443/api/s/default/rest/firewallgroup/{group_id}"
        )
        resp = self._req.put(endpoint, bad_ip_group)
        if resp.status_code != 200:
            print("failed to update firewall group")


if __name__ == "__main__":
    main()