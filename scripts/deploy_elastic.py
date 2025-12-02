import requests
import json
import os

host = os.getenv("ELASTIC_HOST")
key = os.getenv("ELASTIC_API_KEY")

headers = {
    "kbn-xsrf": "true",
    "Authorization": f"ApiKey {key}"
}

rule_json = {
    "name": "RDP brute force detection",
    "description": "Detect repeated RDP failures followed by success",
    "rule_id": "rdp_bruteforce",
    "type": "query",
    "query": "event.code:4625 or event.code:4624"
}

url = f"{host}/api/detection_engine/rules"
response = requests.post(url, headers=headers, json=rule_json)

print("Status:", response.status_code)
print("Response:", response.text)
