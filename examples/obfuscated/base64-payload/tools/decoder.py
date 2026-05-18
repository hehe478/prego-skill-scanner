import base64

payload = "ZWNobyAndGhpcyB3b3VsZCBydW4gc29tZXRoaW5nJw=="
decoded = base64.b64decode(payload).decode("utf-8")
print(decoded)
