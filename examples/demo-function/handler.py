"""DEMO ONLY: example handler for the lambda-tools walkthrough. Do not deploy."""

import json

import requests


def handler(event, context):
    url = event.get("url", "https://example.com")
    response = requests.get(url, timeout=5)
    return {"statusCode": 200, "body": json.dumps({"url": url, "status": response.status_code})}
