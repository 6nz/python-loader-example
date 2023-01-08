# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Login.ui'
#
# Created by: Marci and PyQt5 UI code generator 5.15.4
#
# WARNING! All changes made in this file will be lost!

#  UPDATE: Added live session checking, better protector, re worked the code a little, updated to the latest keyauth example
#  New update soon. (embeds[maybe], error logging through discord/more logging options, toggleable auto-login)

###############################################MODULES###############################################
import binascii  # hex encoding
import hashlib
import json as jsond  # json
import os
# aes + padding, sha256
import os.path
import platform
import threading
from datetime import datetime
import Files.files_rc_rc
import requests
import subprocess
import time
from uuid import uuid4  # gen random guid
import sys
import colorama
import win32con
import win32gui
from colorama import Fore
from pathlib import Path
from threading import Thread
from pyprotector import PythonProtector

###############################################MODULES###############################################

os.system("cls")

###############################################SETTINGS###############################################
windowname = "SkyNet Loader - Login"
hide_console_switch = False  # HIDE CONSOLE SWITCH / Disabled by default, console will auto show after the user logged in(set it to false if u want to see the errors)
live_ban_checking = False  # Disabled by default / checks if the user is banned and auto closes app.
live_session_checking = False  # Disabled by default / checks if the session is valid and not killed.
windowhide = win32gui.GetForegroundWindow()
width = 500
height = 700
###############################################SETTINGS###############################################


###############################################SECURITY###############################################

"""
    ____          ____                __               __
   / __ \\ __  __ / __ \\ _____ ____   / /_ ___   _____ / /_
  / /_/ // / / // /_/ // ___// __ \\ / __// _ \\ / ___// __/
 / ____// /_/ // ____// /   / /_/ // /_ /  __// /__ / /_
/_/     \\__, //_/    /_/    \\____/ \\__/ \\___/ \\___/ \\__/
       /____/

Made With ❤️ By Ghoul & Marci
"""
# -- Define Constants
LOGGING_PATH = (
        Path.home() / "AppData/Roaming/PythonProtector/logs/[Security].log"
)  # -- This can be any path

# -- Construct Class
security = PythonProtector(
    debug=True,
    modules=[
        "AntiProcess",
        "AntiVM",
        "Miscellaneous",
        "AntiDLL",
        "AntiAnalysis"],
    logs_path=LOGGING_PATH,
    webhook_url="webhook here",
    on_detect=[
        "Report",
        "Exit",
        "Screenshot"],
)
###############################################SECURITY###############################################
if hide_console_switch:
    win32gui.ShowWindow(windowhide, win32con.SW_HIDE)
else:
    pass


def slow_type(text, speed, newLine=True):
    for i in text:
        print(i, end="", flush=True)
        time.sleep(speed)
    if newLine:
        print()


def all():  # example console program that will be loaded after register
    print("Hello, this is my test program!")
    time.sleep(10)
    os._exit(1)


try:
    if os.name == 'nt':
        import win32security  # get sid (WIN only)
    import requests  # https requests
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Util.Padding import pad, unpad
except ModuleNotFoundError:
    print("Exception when importing modules")
    print("Installing necessary modules....")
    if os.path.isfile("requirements.txt"):
        os.system("pip install -r requirements.txt")
    else:
        os.system("pip install pywin32")
        os.system("pip install pycryptodome")
        os.system("pip install requests")
    print("Modules installed!")
    time.sleep(1.5)
    os._exit(1)

try:  # Connection check
    s = requests.Session()  # Session
    s.get('https://google.com')
except requests.exceptions.RequestException as e:
    print(e)
    time.sleep(3)
    os._exit(1)


class api:
    name = ownerid = secret = version = hash_to_check = ""

    def __init__(self, name, ownerid, secret, version, hash_to_check):
        self.name = name

        self.ownerid = ownerid

        self.secret = secret

        self.version = version
        self.hash_to_check = hash_to_check
        self.init()

    sessionid = enckey = ""
    initialized = False

    def checkblacklist(self):
        self.checkinit()
        hwid = others.get_hwid()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("checkblacklist".encode()),
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
            return True
        else:
            return False

    def banchecker(self):
        while True:
            try:
                time.sleep(60)
                status = api.checkblacklist(self)
                # print(status)
                if "True" in str(status):
                    print("User banned.")
                    time.sleep(1)
                    os._exit(0)
                else:
                    # Do something
                    pass
            except Exception as e:
                print(e)
                pass

    def checkinit(self):
        if not self.initialized:
            print("Initialize first, in order to use the functions")
            time.sleep(2)
            os._exit(1)

    def initchecker(self):
        while True:
            try:
                time.sleep(120)
                self.checkinit()
            except Exception as e:
                print(e)
                pass

    def init(self):

        if self.sessionid != "":
            print("You've already initialized!")
            time.sleep(2)
            os._exit(1)
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        self.enckey = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("init".encode()),
            "ver": encryption.encrypt(self.version, self.secret, init_iv),
            "hash": self.hash_to_check,
            "enckey": encryption.encrypt(self.enckey, self.secret, init_iv),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)

        if response == "KeyAuth_Invalid":
            print("The application doesn't exist")
            os._exit(1)

        response = encryption.decrypt(response, self.secret, init_iv)
        json = jsond.loads(response)

        if json["message"] == "invalidver":
            if json["download"] != "":
                print("New Version Available")
                download_link = json["download"]
                os.system(f"start {download_link}")
                os._exit(1)
            else:
                print("Invalid Version, Contact owner to add download link to latest app version")
                os._exit(1)

        if not json["success"]:
            print(json["message"])
            os._exit(1)

        self.sessionid = json["sessionid"]
        self.initialized = True
        self.__load_app_data(json["appinfo"])

    def register(self, user, password, license, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("register".encode()),
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
            self.__load_user_data(json["info"])
            # print("Successfully registered! Restarting program...")
            time.sleep(0)
            # python = sys.executable
            # os.execl(python, python, *sys.argv)
        else:
            print(json["message"])
            os._exit(1)

    def login(self, user, password, hwid=None):
        self.checkinit()
        if hwid is None:
            hwid = others.get_hwid()

        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("login".encode()),
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
            hider = win32gui.FindWindowEx(None, None, None, str(windowname))
            win32gui.ShowWindow(hider, win32con.SW_HIDE)
            os.system("cls")
            slow_type(f"{Fore.RED}Successfully logged in! Starting program...{Fore.RESET}", 0.03)
            if live_ban_checking:
                try:
                    # print("Starting ban checking system...")
                    b = threading.Thread(name='Ban Checker', target=api.banchecker, args=(self,))
                    b.start()
                    # print("Started.")
                except:
                    pass
            else:
                pass
            if live_session_checking:
                try:
                    # print("Starting session checking system...")
                    b1 = threading.Thread(name='Session Checker', target=api.checkinit, args=(self,))
                    b1.start()
                    # print("Started.")
                except:
                    pass
            else:
                pass
            time.sleep(1)
            os.system("cls")
            n = int(self.user_data.expires)
            n2 = int(self.user_data.createdate)
            n3 = int(self.user_data.lastlogin)
            slow_type(f"{Fore.RED}Welcome back {Fore.GREEN}{keyauthapp.user_data.username}!", 0.02)  # USER INFO DISPLAY
            slow_type(f"\n{Fore.RED}IP address: {Fore.GREEN}{keyauthapp.user_data.ip}", 0.02)
            slow_type(f"{Fore.RED}Hardware-Id: {Fore.GREEN}{keyauthapp.user_data.hwid}", 0.02)
            slow_type(
                f"{Fore.RED}Created at: {Fore.GREEN}{datetime.utcfromtimestamp(n2).strftime('%Y-%m-%d %H:%M:%S')}",
                0.02)
            slow_type(f"{Fore.RED}Expires at: {Fore.GREEN}{datetime.utcfromtimestamp(n).strftime('%Y-%m-%d %H:%M:%S')}",
                      0.02)
            slow_type(
                f"{Fore.RED}Last login at: {Fore.GREEN}{datetime.utcfromtimestamp(n3).strftime('%Y-%m-%d %H:%M:%S')}{Fore.RESET}",
                0.02)
            time.sleep(2)
            os.system('cls')
            all()
        else:
            print(json["message"])
            time.sleep(2)
            os._exit(1)

    def var(self, name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("var".encode()),
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
            os._exit(1)

    def getvar(self, var_name):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("getvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return json["response"]
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def setvar(self, var_name, var_data):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("setvar".encode()),
            "var": encryption.encrypt(var_name, self.enckey, init_iv),
            "data": encryption.encrypt(var_data, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def ban(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("ban".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            print(json["message"])
            time.sleep(5)
            os._exit(1)

    def file(self, fileid):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("file".encode()),
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
            os._exit(1)
        return binascii.unhexlify(json["contents"])

    def webhook(self, webid, param, body="", conttype=""):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("webhook".encode()),
            "webid": encryption.encrypt(webid, self.enckey, init_iv),
            "params": encryption.encrypt(param, self.enckey, init_iv),
            "body": encryption.encrypt(body, self.enckey, init_iv),
            "conttype": encryption.encrypt(conttype, self.enckey, init_iv),
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
            os._exit(1)

    def check(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()
        post_data = {
            "type": binascii.hexlify("check".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }
        response = self.__do_request(post_data)

        response = encryption.decrypt(response, self.enckey, init_iv)
        json = jsond.loads(response)
        if json["success"]:
            return True
        else:
            return False

    def log(self, message):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("log".encode()),
            "pcuser": encryption.encrypt(os.getenv('username'), self.enckey, init_iv),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        self.__do_request(post_data)

    def fetchOnline(self):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("fetchOnline".encode()),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            if len(json["users"]) == 0:
                return None  # THIS IS ISSUE ON KEYAUTH SERVER SIDE 6.8.2022, so it will return none if it is not an array.
            else:
                return json["users"]
        else:
            return None

    def chatGet(self, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatget".encode()),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return json["messages"]
        else:
            return None

    def chatSend(self, message, channel):
        self.checkinit()
        init_iv = SHA256.new(str(uuid4())[:8].encode()).hexdigest()

        post_data = {
            "type": binascii.hexlify("chatsend".encode()),
            "message": encryption.encrypt(message, self.enckey, init_iv),
            "channel": encryption.encrypt(channel, self.enckey, init_iv),
            "sessionid": binascii.hexlify(self.sessionid.encode()),
            "name": binascii.hexlify(self.name.encode()),
            "ownerid": binascii.hexlify(self.ownerid.encode()),
            "init_iv": init_iv
        }

        response = self.__do_request(post_data)
        response = encryption.decrypt(response, self.enckey, init_iv)

        json = jsond.loads(response)

        if json["success"]:
            return True
        else:
            return False

    def __do_request(self, post_data):
        try:
            rq_out = s.post(
                "https://keyauth.win/api/1.0/", data=post_data, timeout=30
            )
            return rq_out.text
        except requests.exceptions.Timeout:
            print("Request timed out")

    class application_data_class:
        numUsers = numKeys = app_ver = customer_panel = onlineUsers = ""

    # region user_data

    class user_data_class:
        username = ip = hwid = expires = createdate = lastlogin = subscription = subscriptions = ""

    user_data = user_data_class()
    app_data = application_data_class()

    def __load_app_data(self, data):
        self.app_data.numUsers = data["numUsers"]
        self.app_data.numKeys = data["numKeys"]
        self.app_data.app_ver = data["version"]
        self.app_data.customer_panel = data["customerPanelLink"]
        self.app_data.onlineUsers = data["numOnlineUsers"]

    def __load_user_data(self, data):
        self.user_data.username = data["username"]
        self.user_data.ip = data["ip"]
        self.user_data.hwid = data["hwid"]
        self.user_data.expires = data["subscriptions"][0]["expiry"]
        self.user_data.createdate = data["createdate"]
        self.user_data.lastlogin = data["lastlogin"]
        self.user_data.subscription = data["subscriptions"][0]["subscription"]
        self.user_data.subscriptions = data["subscriptions"]


class others:
    @staticmethod
    def get_hwid():
        if platform.system() == "Linux":
            with open("/etc/machine-id") as f:
                hwid = f.read()
                return hwid
        elif platform.system() == 'Windows':
            winuser = os.getlogin()
            sid = win32security.LookupAccountName(None, winuser)[
                0]  # You can also use WMIC (better than SID, some users had problems with WMIC)
            hwid = win32security.ConvertSidToStringSid(sid)
            return hwid
        elif platform.system() == 'Darwin':
            output = subprocess.Popen("ioreg -l | grep IOPlatformSerialNumber", stdout=subprocess.PIPE,
                                      shell=True).communicate()[0]
            serial = output.decode().split('=', 1)[1].replace(' ', '')
            hwid = serial[1:-2]
            return hwid


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
            print(
                "Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            os._exit(1)

    @staticmethod
    def decrypt(message, enc_key, iv):
        try:
            _key = SHA256.new(enc_key.encode()).hexdigest()[:32]

            _iv = SHA256.new(iv.encode()).hexdigest()[:16]

            return encryption.decrypt_string(message.encode(), _key.encode(), _iv.encode()).decode()
        except:
            print(
                "Invalid Application Information. Long text is secret short text is ownerid. Name is supposed to be app name not username")
            os._exit(1)


os.system("cls")


def getchecksum():
    md5_hash = hashlib.md5()
    file = open(''.join(sys.argv), "rb")
    md5_hash.update(file.read())
    digest = md5_hash.hexdigest()
    return digest


keyauthapp = api(
    name = "", #App name (Manage Applications --> Application name)
    ownerid = "", #Owner ID (Account-Settings --> OwnerID)
    secret = "", #App secret(Manage Applications --> App credentials code)
    version = "1.0",
    hash_to_check = getchecksum()
)

colorama.init()
# FILE CHECK
try:
    if os.path.isfile('Files/auth.json'):
        if jsond.load(open("Files/auth.json"))["authusername"] == "":
            pass
        else:
            try:
                with open('Files/auth.json', 'r') as f:
                    authfile = jsond.load(f)
                    authuser = authfile.get('authusername')
                    authpass = authfile.get('authpassword')
                    win32gui.ShowWindow(windowhide, win32con.SW_SHOW)
                    keyauthapp.login(authuser, authpass)
            except Exception as e:
                print(e)
    else:
        try:
            f = open("Files/auth.json", "a")
            f.write("""{
"authusername": "",
"authpassword": ""
}""")
            f.close()
        except Exception as e:
            print(e)

except Exception as e:
    print(f"Error while loading auth file... check if the auth file is missing/empty or not ERROR CODE: {e}")
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
            license = self.lineEdit_license.text()
            if self.checkBox_save_user.isChecked():
                if self.checkBox_register_user.isChecked():
                    import json as jason
                    config = jason.load(open("Files/auth.json"))
                    config["authusername"] = (self.lineEdit_user.text())
                    jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                    config["authpassword"] = (self.lineEdit_password.text())
                    jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                    try:
                        win32gui.ShowWindow(windowhide, win32con.SW_SHOW)
                        keyauthapp.register(user, password, license)
                        time.sleep(1)
                        keyauthapp.login(user, password)
                    except Exception as e:
                        print(e)
                else:
                    try:
                        import json as jason
                        config = jason.load(open("Files/auth.json"))
                        config["authusername"] = (self.lineEdit_user.text())
                        jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                        config["authpassword"] = (self.lineEdit_password.text())
                        jason.dump(config, open('Files/auth.json', 'w'), sort_keys=False, indent=4)
                        win32gui.ShowWindow(windowhide, win32con.SW_SHOW)
                        keyauthapp.login(user, password)
                    except Exception as e:
                        print(e)
            else:
                if self.checkBox_register_user.isChecked():
                    try:
                        win32gui.ShowWindow(windowhide, win32con.SW_SHOW)
                        keyauthapp.register(user, password, license)
                        time.sleep(1)
                        keyauthapp.login(user, password)
                    except Exception as e:
                        print(e)
                else:
                    try:
                        win32gui.ShowWindow(windowhide, win32con.SW_SHOW)
                        keyauthapp.login(user, password)
                    except Exception as e:
                        print(e)

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(500, 752)
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
        self.frame_error.setStyleSheet("background-color: rgb(255, 85, 127);\n"
                                       "border-radius: 5px;")
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
        self.pushButton_close_pupup = QtWidgets.QPushButton(self.frame_error)
        self.pushButton_close_pupup.setMaximumSize(QtCore.QSize(20, 20))
        self.pushButton_close_pupup.setStyleSheet("QPushButton {\n"
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
        self.pushButton_close_pupup.setText("")
        self.pushButton_close_pupup.setObjectName("pushButton_close_pupup")
        self.horizontalLayout_3.addWidget(self.pushButton_close_pupup)
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
        self.logo.setGeometry(QtCore.QRect(30, 10, 381, 150))
        self.logo.setStyleSheet("background-image: url(:/Logo/Images/logo_360x90.png);\n"
                                "background-repeat: no-repeat;\n"
                                "background-position: center;")
        self.logo.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.logo.setFrameShadow(QtWidgets.QFrame.Raised)
        self.logo.setObjectName("logo")
        self.lineEdit_user = QtWidgets.QLineEdit(self.login_area)
        self.lineEdit_user.setGeometry(QtCore.QRect(85, 220, 280, 50))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.lineEdit_user.setFont(font)
        self.lineEdit_user.setStyleSheet("QLineEdit {\n"
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
        self.lineEdit_user.setMaxLength(32)
        self.lineEdit_user.setObjectName("lineEdit_user")
        self.lineEdit_password = QtWidgets.QLineEdit(self.login_area)
        self.lineEdit_password.setEnabled(True)
        self.lineEdit_password.setGeometry(QtCore.QRect(85, 280, 280, 50))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.lineEdit_password.setFont(font)
        self.lineEdit_password.setStyleSheet("QLineEdit {\n"
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
        self.lineEdit_password.setMaxLength(16)
        self.lineEdit_password.setEchoMode(QtWidgets.QLineEdit.Password)
        self.lineEdit_password.setReadOnly(False)
        self.lineEdit_password.setObjectName("lineEdit_password")
        self.checkBox_save_user = QtWidgets.QCheckBox(self.login_area)
        self.checkBox_save_user.setGeometry(QtCore.QRect(85, 400, 161, 21))
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
        self.pushButton_login.setGeometry(QtCore.QRect(85, 460, 280, 50))
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
        self.checkBox_register_user = QtWidgets.QCheckBox(self.login_area)
        self.checkBox_register_user.setGeometry(QtCore.QRect(85, 430, 181, 21))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.checkBox_register_user.setFont(font)
        self.checkBox_register_user.setStyleSheet("QCheckBox::indicator {\n"
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
        self.checkBox_register_user.setObjectName("checkBox_register_user")
        self.lineEdit_license = QtWidgets.QLineEdit(self.login_area)
        self.lineEdit_license.setGeometry(QtCore.QRect(85, 340, 280, 50))
        font = QtGui.QFont()
        font.setFamily("Segoe UI")
        font.setPointSize(10)
        self.lineEdit_license.setFont(font)
        self.lineEdit_license.setStyleSheet("QLineEdit {\n"
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
        self.lineEdit_license.setMaxLength(32)
        # self.lineEdit_license.setReadOnly(True)
        self.lineEdit_license.setObjectName("lineEdit_license")
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
        self.label_credits.setAlignment(QtCore.Qt.AlignRight | QtCore.Qt.AlignTrailing | QtCore.Qt.AlignVCenter)
        self.label_credits.setObjectName("label_credits")
        self.verticalLayout_2.addWidget(self.label_credits)
        self.verticalLayout.addWidget(self.bottom)
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 500, 21))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        # setting  the fixed size of window
        MainWindow.setFixedSize(width, height)

        #
        # FUNCTIONS
        #

        # BT CLOSE POPUP
        self.pushButton_close_pupup.clicked.connect(lambda: self.frame_error.hide())

        # HIDE ERROR
        self.frame_error.hide()

        # BT LOGIN
        self.pushButton_login.clicked.connect(self.checkFields)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", windowname))
        self.label_error.setText(_translate("MainWindow", "Error"))
        self.lineEdit_user.setToolTip(
            _translate("MainWindow", "<html><head/><body><p>Username goes here.</p></body></html>"))
        self.lineEdit_user.setPlaceholderText(_translate("MainWindow", "USERNAME"))
        self.lineEdit_password.setToolTip(
            _translate("MainWindow", "<html><head/><body><p>Password goes here.</p></body></html>"))
        self.lineEdit_password.setPlaceholderText(_translate("MainWindow", "PASSWORD"))
        self.checkBox_save_user.setToolTip(_translate("MainWindow",
                                                      "<html><head/><body><p>Use this option if u want to save the username and password for auto-login.</p></body></html>"))
        self.checkBox_save_user.setText(_translate("MainWindow", "Save User"))
        self.pushButton_login.setToolTip(
            _translate("MainWindow", "<html><head/><body><p>Load the program.</p></body></html>"))
        self.pushButton_login.setText(_translate("MainWindow", "Load Program"))
        self.checkBox_register_user.setToolTip(_translate("MainWindow",
                                                          "<html><head/><body><p>Use this option if u don\'t have an account.</p></body></html>"))
        self.checkBox_register_user.setText(_translate("MainWindow", "Register User"))
        self.label_credits.setToolTip(_translate("MainWindow", "<html><head/><body><p>SKYNET</p></body></html>"))
        self.lineEdit_license.setPlaceholderText(_translate("MainWindow", "LICENSE"))
        self.lineEdit_license.setToolTip(_translate("MainWindow",
                                                    "<html><head/><body><p>Only if u want to register! Key goes here...</p></body></html>"))
        self.label_credits.setText(_translate("MainWindow", "Created by: SkyNet"))


if __name__ == "__main__":
    SecurityThread = Thread(
        name="Python Protector", target=security.start
    )  # -- Start Before Any Other Code Is Run
    SecurityThread.start()
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
