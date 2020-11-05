from azure.storage.queue import QueueClient
from azure.cosmosdb.table.tableservice import TableService
from azure.cosmosdb.table.models import Entity
import os, time, base64, json, requests, sys, datetime

def main():
    connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
    username = os.getenv("UNIFI_USERNAME")
    password = os.getenv("UNIFI_PASSWORD")
    unifi_controller = os.getenv("UNIFI_CONTROLLER")
    evict_after = os.getenv("EVICT_AFTER_DAYS", 7)
    updater = FirewallUpdater(unifi_controller, username, password)
    data_service = DataService(connect_str)
    queue_name = "threatsignals"
    queue_client = QueueClient.from_connection_string(connect_str, queue_name)
    while True:
        messages = queue_client.receive_messages()
        count = 0
        for msg in messages:
            decoded = base64.b64decode(msg.content)
            message = json.loads(decoded)
            if "ip" in message:
                handle_ip_signal(message)
            elif "domain" in message:
                handle_domain_signal(message)
            elif "url" in message:
                handle_url_signal(message)
            
            count += 1
            queue_client.delete_message(msg)
        print(f"=> processed {count} messages")
        print(f"* Evicting expired (older than {evict_after} days) entries...")
        expired = data_service.get_expired_ips(evict_after)
        count = 0
        for ip in expired:
            print(f"-> {ip.RowKey}")
            count += 1
            updater.remove_ip_from_group("Block IPs", ip.RowKey)
            data_service.remove_ip(ip.RowKey)
        print(f"=> {count} IPs evicted")
        time.sleep(300)

def handle_domain_signal(message : dict):
    pass

def handle_url_signal(message : dict):
    pass

def handle_ip_signal(message: dict):
    malicious_reports = message["malicious"]
    if malicious_reports > 0:
        ip = reported_ip["ip"]
        alert = reported_ip["alert"]
        print(
            f"-> [{alert}] {ip} is reported as malicious by {malicious_reports} sources - adding to blocklist"
        )

        data_service.add_or_update_ip(ip, alert)
        updater.add_ip_to_group("Block IPs", ip)


class DataService:
    def __init__(self, connection_string: str):
        self._table_name = "BlockedIPs"
        self._table_service = TableService(connection_string=connection_string)
        self._ensure_table()

    def _ensure_table(self):
        if self._table_service.exists(self._table_name):
            return
        self._table_service.create_table(self._table_name)

    def add_or_update_ip(self, ip: str, alert_type: str):
        ip_entity = Entity()
        ip_entity.PartitionKey = "ip"
        ip_entity.RowKey = ip
        ip_entity.LastSeen = datetime.datetime.utcnow()
        ip_entity.AlertType = alert_type
        self._table_service.insert_or_replace_entity(self._table_name, ip_entity)

    def remove_ip(self, ip: str):
        self._table_service.delete_entity(self._table_name, "ip", ip)

    def get_expired_ips(self, age_days: int = 7):
        expired_date = datetime.datetime.now() - datetime.timedelta(days=age_days)
        expired_date_utc = datetime.datetime.utcfromtimestamp(
            expired_date.timestamp()
        ).isoformat()
        return self._table_service.query_entities(
            self._table_name, filter="LastSeen lt datetime'" + expired_date_utc + "'"
        )


class FirewallUpdater:
    def __init__(self, url: str, username: str, password: str):
        self.url = url
        self._req = requests.Session()
        self._req.headers["Content-Type"] = "application/json;charset=utf-8"
        self._bad_ip_group = None
        self._username = username
        self._password = password

    def _login(self, username: str, password: str):
        self._req.post(
            f"https://{self.url}:8443/api/login",
            f'{{"username": "{username}", "password":"{password}"}}',
        )

    def _get_firewall_groups(self) -> dict:
        endpoint = f"https://{self.url}:8443/api/s/default/rest/firewallgroup"
        data = self._req.get(endpoint).json()
        return data["data"]

    def _ensure_group_data(self, group_name: str):
        if not self._bad_ip_group:
            groups = self._get_firewall_groups()
            bad_ip_group = [g for g in groups if g["name"] == "Block IPs"]
            if len(bad_ip_group) == 0:
                print("Did not find firewall group")
                sys.exit(1)

            bad_ip_group = bad_ip_group[0]
            self._bad_ip_group = bad_ip_group

    def add_ip_to_group(self, group_name: str, ip_addr: str):
        self._login(self._username, self._password)
        self._ensure_group_data(group_name)

        ips = self._bad_ip_group["group_members"]
        if ip_addr in ips:
            print(f"-> {ip_addr} already registered - skipping")
            return

        ips.append(ip_addr)
        self._bad_ip_group["group_members"] = ips
        self._update_group()

    def remove_ip_from_group(self, group_name: str, ip_addr: str):
        self._login(self._username, self._password)
        self._ensure_group_data(group_name)
        if ip_addr in self._bad_ip_group["group_members"]:
            self._bad_ip_group["group_members"].remove(ip_addr)
        self._update_group()

    def _update_group(self):
        group_id = self._bad_ip_group["_id"]
        endpoint = (
            f"https://{self.url}:8443/api/s/default/rest/firewallgroup/{group_id}"
        )
        resp = self._req.put(endpoint, json.dumps(self._bad_ip_group))
        if resp.status_code != 200:
            print(f"!! failed to update firewall group: {resp.reason}")


if __name__ == "__main__":
    main()