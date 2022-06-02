"""
AWVS api Tests
"""

BASE_URL = "https://192.168.204.129:3443/api/v1/"

# scans/63802f05-615b-417b-9185-00e07c309292/results/7689eefb-0b0f-4325-9a17-1a6b16d41eda/vulnerabilities?c=0&l=1000

r = requests.get(url="{}/scans/63802f05-615b-417b-9185-00e07c309292/results/7689eefb-0b0f-4325-9a17-1a6b16d41eda/vulnerabilities?c=0&l=1000".format(BASE_URL))

print(r.json())
