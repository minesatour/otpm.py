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
import sqlite3
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
import subprocess

# 🔹 CONFIGURATIONS
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
OTP_STORAGE_FILE = "captured_otps.db"
otp_pattern = r"\b\d{6}\b"
mitmproxy_port = 8082

# 🔹 PROXY SETTINGS (USE REAL PROXY HERE)
PROXY_HOST = "your-proxy-ip"
PROXY_PORT = "your-proxy-port"
PROXY_USERNAME = "your-username"
PROXY_PASSWORD = "your-password"

# 🔹 ENCRYPTION KEY (STORED IN MEMORY)
key = get_random_bytes(16)

# 🔹 SETUP DATABASE
def setup_database():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY, otp TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()

# 🔹 FUNCTION TO ENCRYPT & STORE OTP IN DATABASE
def store_otp(otp):
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, _ = cipher.encrypt_and_digest(otp.encode('utf-8'))
    c.execute("INSERT INTO otps (otp) VALUES (?)", (ciphertext.hex(),))
    conn.commit()
    conn.close()

# 🔹 KILL EXISTING PROCESSES ON PORT 8082
def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                print(f"✅ Terminated process {conn.pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

# 🔹 GUI TO DISPLAY OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x150")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)

    def update_otp(self, otp):
        store_otp(otp)
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# 🔹 MITMPROXY INTERCEPTOR
class OTPInterceptor:
    def __init__(self):
        self.gui = None
        self.waiting_for_otp = False

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if "otp" in flow.request.url.lower() and self.waiting_for_otp:
            content = flow.response.content.decode(errors='replace')
            otp_matches = re.findall(otp_pattern, content)
            if otp_matches:
                otp = otp_matches[0]
                if self.gui:
                    self.gui.update_otp(otp)
                    print(f"✅ Captured OTP from {flow.request.url}: {otp}")
            self.waiting_for_otp = False

    def wait_for_otp(self):
        self.waiting_for_otp = True
        print("🚀 Waiting for OTP request...")

# 🔹 START MITMPROXY IN BACKGROUND
def start_mitmproxy(interceptor):
    options = Options(listen_host='127.0.0.1', listen_port=mitmproxy_port, ssl_insecure=True)
    m = DumpMaster(options)
    m.addons.add(interceptor)
    m.run()

def run_mitmproxy_thread(interceptor):
    mitmproxy_thread = threading.Thread(target=start_mitmproxy, args=(interceptor,))
    mitmproxy_thread.daemon = True
    mitmproxy_thread.start()

# 🔹 LAUNCH CHROME WITH PROXY & MITMPROXY
def launch_chrome(target_url, use_mitmproxy):
    chrome_options = ChromeOptions()

    if use_mitmproxy:
        chrome_options.add_argument(f"--proxy-server=http://127.0.0.1:{mitmproxy_port}")
    else:
        chrome_options.add_argument(f"--proxy-server=http://{PROXY_USERNAME}:{PROXY_PASSWORD}@{PROXY_HOST}:{PROXY_PORT}")

    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--headless")  # Remove if you want to see the browser
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

# 🔹 JAVASCRIPT OTP EXTRACTION
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

# 🔹 AUTOMATIC OTP EXTRACTION
def auto_extract_otp(driver, interceptor, gui):
    otp = extract_otp_via_js(driver)
    if otp:
        gui.update_otp(otp)
        print(f"✅ Captured OTP via JavaScript: {otp}")
    else:
        print("⚠ No OTP found via JavaScript, switching to mitmproxy...")
        interceptor.wait_for_otp()
        run_mitmproxy_thread(interceptor)

# 🔹 MAIN FUNCTION
def main():
    kill_processes_using_port(mitmproxy_port)
    setup_database()

    root = tk.Tk()
    gui = OTPGUI(root)
    interceptor = OTPInterceptor()
    interceptor.set_gui(gui)

    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")

    messagebox.showinfo("Action Required", "🚀 Script will auto-detect OTP extraction method.")
    
    driver = launch_chrome(target_url, use_mitmproxy=True)
    
    auto_extract_otp(driver, interceptor, gui)
    
    root.mainloop()
    driver.quit()

if __name__ == "__main__":
    main()
