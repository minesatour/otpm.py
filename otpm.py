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
import requests

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium_stealth import stealth
import re
import subprocess
import time

# CONFIGURATIONS
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"  # Make sure this is correct
OTP_STORAGE_FILE = "captured_otps.db"
# More specific OTP pattern (adjust as needed)
otp_pattern = r"\b\d{6}\b"  # Example: 6 digits
mitmproxy_port = 8082

# FREE PROXY API (Consider a paid service for production)
PROXY_API_URL = "https://www.proxy-list.download/api/v1/get?type=http"

# SETUP DATABASE
def setup_database():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY, otp TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()

# FUNCTION TO ENCRYPT & STORE OTP IN DATABASE (Placeholder - Implement secure key management)
def store_otp(otp):
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    # In real application, do not store the key in the code, use environment variables or key management system.
    cipher = AES.new(b'Sixteen byte key', AES.MODE_EAX) # Example, not secure.
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(otp.encode('utf-8'))
    c.execute("INSERT INTO otps (otp, nonce, tag) VALUES (?, ?, ?)", (ciphertext.hex(), nonce.hex(), tag.hex()))
    conn.commit()
    conn.close()

# KILL EXISTING PROCESSES ON PORT 8082
def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                print(f"✅ Terminated process {conn.pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

# FETCH A FREE PROXY (Use with caution)
def get_free_proxy():
    try:
        response = requests.get(PROXY_API_URL, timeout=5)  # Timeout added
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        proxies = response.text.strip().split("\r\n")
        if proxies:
            return proxies[0]  # Return the first available proxy
    except requests.exceptions.RequestException as e:
        print(f"⚠ Failed to fetch proxy: {e}")
    return None

# GUI TO DISPLAY OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x150")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)
        self.status_label = tk.Label(master, text="", font=("Arial", 10)) # Status label
        self.status_label.pack()

    def update_otp(self, otp):
        store_otp(otp)
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")
        self.status_label.config(text="")

    def update_status(self, message):
        self.status_label.config(text=message)


# MITMPROXY INTERCEPTOR
class OTPInterceptor:
    def __init__(self):
        self.gui = None
        self.waiting_for_otp = False

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if self.waiting_for_otp:
            try:
                content = flow.response.content.decode(errors='replace')
                otp_matches = re.findall(otp_pattern, content)
                if otp_matches:
                    otp = otp_matches[0]
                    if self.gui:
                        self.gui.update_otp(otp)
                        print(f"✅ Captured OTP from {flow.request.url}: {otp}")
                self.waiting_for_otp = False
            except Exception as e:
                print(f"Error processing response: {e}")
                if self.gui:
                  self.gui.update_status(f"Error: {e}")


    def wait_for_otp(self):
        self.waiting_for_otp = True
        if self.gui:
            self.gui.update_status("Waiting for OTP...")
        print("🚀 Waiting for OTP request...")

# START MITMPROXY IN BACKGROUND
def start_mitmproxy(interceptor):
    options = Options(listen_host='127.0.0.1', listen_port=mitmproxy_port, ssl_insecure=True) # ssl_insecure for testing only
    m = DumpMaster(options)
    m.addons.add(interceptor)
    print(f"🔧 Starting mitmproxy on {mitmproxy_port}...")
    try:
        m.run()
    except Exception as e:
        print(f"mitmproxy error: {e}")

def run_mitmproxy_thread(interceptor):
    mitmproxy_thread = threading.Thread(target=start_mitmproxy, args=(interceptor,))
    mitmproxy_thread.daemon = True
    mitmproxy_thread.start()

# LAUNCH CHROME WITH PROXY & MITMPROXY
def launch_chrome(target_url):
    chrome_options = ChromeOptions()
    free_proxy = get_free_proxy()

    if free_proxy:
        print(f"🆓 Using free proxy: {free_proxy}")
        chrome_options.add_argument(f"--proxy-server=http://{free_proxy}")
    else:
        print("⚠ No free proxies available. Continuing without proxy.")  # Don't exit, but warn the user

    # Remove these for real use:
    # chrome_options.add_argument("--ignore-certificate-errors")  # Insecure
    # chrome_options.add_argument("--disable-web-security")  # Insecure
    # chrome_options.add_argument("--no-sandbox") # Extremely Insecure

    chrome_options.add_argument("--headless")  # Keep headless
    chrome_options.add_argument("--disable-gpu")

    try:
        driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
        stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32", webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
        driver.get(target_url)
        driver.maximize_window()
        driver.implicitly_wait(10)
        return driver
    except Exception as e:
        print(f"Error launching Chrome: {e}")
        return None

# MAIN FUNCTION
def main():
    kill_processes_using_port(mitmproxy_port)
    setup_database()

    root = tk.Tk()
    gui = OTPGUI(root)
    interceptor = OTPInterceptor()
    interceptor.set_gui(gui)

    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    if not target_url:  # Handle cancel
        return

    messagebox.showinfo("Action Required", "🚀 Script will attempt OTP extraction.")

    driver = launch_chrome(target_url)
    if not driver:
        gui.update_status("Failed to launch browser.")  # Update status in GUI
        return

    interceptor.wait_for_otp()
    run_mitmproxy_
