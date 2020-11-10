import requests

url = "https://snail.racecraft.cf/"

session = requests.Session()
resp = session.get(url + "/check")
print(resp.text)
print(resp.status_code)