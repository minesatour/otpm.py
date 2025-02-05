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
import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service

# Path to ChromeDriver
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
ALLOWED_SITES_FILE = "allowed_sites.txt"
OTP_STORAGE_FILE = "captured_otps.enc"

otp_pattern = r"\b\d{6}\b"
key = get_random_bytes(16)  # AES encryption key

def encrypt_otp(otp):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(otp.encode('utf-8'))
    with open(OTP_STORAGE_FILE, "wb") as f:
        f.write(nonce + ciphertext)

def decrypt_otp():
    with open(OTP_STORAGE_FILE, "rb") as f:
        data = f.read()
    nonce, ciphertext = data[:16], data[16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode('utf-8')

def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                proc.terminate()
                print(f"Terminated process {conn.pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

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

async def start_mitmproxy(gui, allowed_sites, interceptor):
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    m = DumpMaster(options)
    interceptor.set_gui(gui)
    m.addons.add(interceptor)
    await m.run()

def launch_chrome(target_url):
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument(f"--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    driver.get(target_url)
    driver.maximize_window()
    driver.implicitly_wait(10)
    return driver

def load_allowed_sites():
    if not os.path.exists(ALLOWED_SITES_FILE):
        return []
    with open(ALLOWED_SITES_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def main():
    kill_processes_using_port(8080)
    allowed_sites = load_allowed_sites()
    root = tk.Tk()
    gui = OTPGUI(root)
    interceptor = OTPInterceptor(allowed_sites)
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    mitm_thread = threading.Thread(target=lambda: asyncio.run(start_mitmproxy(gui, allowed_sites, interceptor)))
    mitm_thread.start()
    driver = launch_chrome(target_url)
    messagebox.showinfo("Action Required", "Log in and request an OTP, then click OK to start interception.")
    interceptor.wait_for_otp()
    driver.quit()  # Ensure Chrome stays open until the user closes it manually
    root.mainloop()

if __name__ == "__main__":
    main()
