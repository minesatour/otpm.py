import asyncio
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

import tkinter as tk
from tkinter import messagebox, simpledialog
import re
import threading
import os
import psutil
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium_stealth import stealth

# Path to ChromeDriver
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
ALLOWED_SITES_FILE = "allowed_sites.txt"
OTP_STORAGE_FILE = "captured_otps.enc"

otp_pattern = r"\b\d{6}\b"
key = get_random_bytes(16)  # AES encryption key

# List of proxies for rotation
PROXY_LIST = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
]

# List of user agents for rotation
USER_AGENT_LIST = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36",
]

# Function to encrypt OTP
def encrypt_otp(otp):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(otp.encode('utf-8'))
    with open(OTP_STORAGE_FILE, "wb") as f:
        f.write(nonce + ciphertext)

# Function to decrypt OTP
def decrypt_otp():
    with open(OTP_STORAGE_FILE, "rb") as f:
        data = f.read()
    nonce, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Kill processes using a specific port (needed for mitmproxy cleanup)
def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                print(f"Terminated process {conn.pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

# Function to get a random proxy from the list
def get_random_proxy():
    return random.choice(PROXY_LIST)

# Function to get a random user agent from the list
def get_random_user_agent():
    return random.choice(USER_AGENT_LIST)

# Function to setup Tor Proxy (optional)
def setup_tor_proxy():
    return "socks5://127.0.0.1:9050"

# Function to apply fingerprint masking using selenium-stealth
def apply_browser_fingerprints(driver):
    stealth(driver,
            user_agent=get_random_user_agent(),
            languages=["en-US", "en"],
            pass_modified=True,
            navigator_languages=["en-US", "en"],
            webgl_vendor="Intel Inc.",
            webgl_renderer="Intel Iris OpenGL Engine",
            fix_hairline=True,
            webgl_force=True,
            spoof_window_size=True,
            renderer="Apple"
    )
    return driver

# Function to launch Chrome with proxies, user-agent, and optional Tor
def launch_chrome(target_url, use_js_injection, use_proxy=False, use_tor=False):
    chrome_options = ChromeOptions()

    # Use Tor proxy if enabled
    if use_tor:
        proxy = setup_tor_proxy()
        chrome_options.add_argument(f"--proxy-server={proxy}")
    elif use_proxy:
        proxy = get_random_proxy()  # Regular proxy rotation
        chrome_options.add_argument(f"--proxy-server={proxy}")

    # Set random user-agent to prevent tracking via user-agent
    chrome_options.add_argument(f"--user-agent={get_random_user_agent()}")
    
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    
    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    driver = apply_browser_fingerprints(driver)  # Mask fingerprints
    
    driver.get(target_url)
    driver.maximize_window()
    driver.implicitly_wait(10)
    return driver

# Class to display OTP GUI
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x150")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)

    def update_otp(self, otp):
        encrypt_otp(otp)
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# Class to intercept OTPs using mitmproxy
class OTPInterceptor:
    def __init__(self, allowed_sites):
        self.gui = None
        self.allowed_sites = allowed_sites
        self.waiting_for_otp = False

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if any(site in flow.request.url for site in self.allowed_sites) and self.waiting_for_otp:
            content = flow.response.content.decode(errors='replace')
            otp_matches = re.findall(otp_pattern, content)
            if otp_matches:
                otp = otp_matches[0]
                if self.gui:
                    self.gui.update_otp(otp)
                    print(f"Captured OTP from {flow.request.url}: {otp}")
            self.waiting_for_otp = False

    def wait_for_otp(self):
        self.waiting_for_otp = True
        print("Waiting for OTP request...")

# Asynchronous function to run mitmproxy
async def start_mitmproxy(gui, allowed_sites, interceptor):
    options = Options(listen_host='127.0.0.1', listen_port=8082, ssl_insecure=True)
    m = DumpMaster(options)
    interceptor.set_gui(gui)
    m.addons.add(interceptor)
    await m.run()

# Function to load allowed sites from file
def load_allowed_sites():
    if not os.path.exists(ALLOWED_SITES_FILE):
        return []
    with open(ALLOWED_SITES_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Main function
def main():
    kill_processes_using_port(8082)
    allowed_sites = load_allowed_sites()
    root = tk.Tk()
    gui = OTPGUI(root)
    interceptor = OTPInterceptor(allowed_sites)
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    
    # Ask user if they want to use proxies or Tor
    use_proxy = simpledialog.askstring("Proxy Option", "Do you want to use a proxy? (yes/no)").lower() == "yes"
    use_tor = simpledialog.askstring("Tor Option", "Do you want to use Tor? (yes/no)").lower() == "yes"
    
    mitm_thread = threading.Thread(target=lambda: asyncio.run(start_mitmproxy(gui, allowed_sites, interceptor)))
    mitm_thread.start()
    
    # Launch Chrome with options
    driver = launch_chrome(target_url, use_js_injection=False, use_proxy=use_proxy, use_tor=use_tor)
    
    messagebox.showinfo("Action Required", "Log in and request an OTP, then click OK to start interception.")
    interceptor.wait_for_otp()
    
    root.mainloop()

# Run the script
if __name__ == "__main__":
    main()
