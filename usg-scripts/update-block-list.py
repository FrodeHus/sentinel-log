from azure.storage.queue import QueueServiceClient, QueueClient, QueueMessage
import os, uuid, base64, json

connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
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
    queue_client.delete_message(msg)
