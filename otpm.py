import asyncio
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

import tkinter as tk
from tkinter import messagebox, simpledialog
import threading
import os
import psutil
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth
import re

# Paths and Configurations
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
ALLOWED_SITES_FILE = "allowed_sites.txt"
OTP_STORAGE_FILE = "captured_otps.enc"
otp_pattern = r"\b\d{6}\b"
key = get_random_bytes(16)  # AES encryption key
PROXY_SERVER = "http://your-proxy-provider.com:port"  # Replace with real proxy

# Function to encrypt OTPs
def encrypt_otp(otp):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(otp.encode('utf-8'))
    with open(OTP_STORAGE_FILE, "wb") as f:
        f.write(nonce + ciphertext)

# Function to decrypt OTPs
def decrypt_otp():
    with open(OTP_STORAGE_FILE, "rb") as f:
        data = f.read()
    nonce, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

# Kill processes using port 8082
def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                print(f"Terminated process {conn.pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

# GUI to display captured OTP
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

# mitmproxy Interceptor
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

# Start mitmproxy
async def start_mitmproxy(gui, allowed_sites, interceptor):
    options = Options(listen_host='127.0.0.1', listen_port=8082, ssl_insecure=True)
    m = DumpMaster(options)
    interceptor.set_gui(gui)
    m.addons.add(interceptor)
    await m.run()

# Launch Chrome with Stealth Mode and Proxy
def launch_chrome(target_url, use_mitmproxy, interactive_mode=False):
    chrome_options = ChromeOptions()

    if use_mitmproxy:
        chrome_options.add_argument("--proxy-server=http://127.0.0.1:8082")
    else:
        chrome_options.add_argument(f"--proxy-server={PROXY_SERVER}")

    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

    if interactive_mode:
        chrome_options.add_argument("--incognito")
        chrome_options.add_argument("--start-maximized")
    else:
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")

    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    
    # Apply Selenium Stealth
    stealth(driver,
        languages=["en-US", "en"],
        vendor="Google Inc.",
        platform="Win32",
        webgl_vendor="Intel Inc.",
        renderer="Intel Iris OpenGL Engine",
        fix_hairline=True,
    )

    driver.get(target_url)
    driver.maximize_window()
    driver.implicitly_wait(10)
    return driver

# JavaScript Injection to Extract OTP
def extract_otp_via_js(driver):
    try:
        wait = WebDriverWait(driver, 15)
        otp_element = wait.until(EC.presence_of_element_located((By.XPATH, "//*[contains(text(), 'code') or contains(text(), 'OTP')]")))
        otp_text = otp_element.text
        otp_matches = re.findall(otp_pattern, otp_text)
        if otp_matches:
            return otp_matches[0]
    except Exception:
        pass
    return None

# Load allowed sites
def load_allowed_sites():
    if not os.path.exists(ALLOWED_SITES_FILE):
        return []
    with open(ALLOWED_SITES_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Automatic OTP Extraction Mode
def auto_extract_otp(driver, interceptor, gui):
    otp = extract_otp_via_js(driver)
    if otp:
        gui.update_otp(otp)
        print(f"Captured OTP automatically via JavaScript: {otp}")
    else:
        print("No OTP found via JavaScript.")
    interceptor.wait_for_otp()
    asyncio.run(start_mitmproxy(gui, load_allowed_sites(), interceptor))

# Main function
def main():
    kill_processes_using_port(8082)
    allowed_sites = load_allowed_sites()
    root = tk.Tk()
    gui = OTPGUI(root)
    interceptor = OTPInterceptor(allowed_sites)
    
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    driver = launch_chrome(target_url, use_mitmproxy=True, interactive_mode=True)
    auto_extract_otp(driver, interceptor, gui)
    root.mainloop()
    driver.quit()

if __name__ == "__main__":
    main()
