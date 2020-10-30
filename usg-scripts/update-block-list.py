from azure.storage.queue import QueueServiceClient, QueueClient, QueueMessage
import os, uuid, base64, json

connect_str = os.getenv("AZURE_STORAGE_CONNECTION_STRING")
queue_name = "threatsignals"

queue_client = QueueClient.from_connection_string(connect_str, queue_name)
messages = queue_client.receive_messages()
for msg in messages:
    decoded = base64.b64decode(msg.content)
    reported_ip = json.loads(decoded)
    if reported_ip.malicious > 0:
        print(
            f"IP {reported_ip.ip} is reported as malicious by {reported_ip.malicious} - adding to blocklist"
        )
