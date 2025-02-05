import asyncio
import mitmproxy.http
from mitmproxy import ctx
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

import tkinter as tk
from tkinter import messagebox, simpledialog
import re
import threading
import time
import os
import psutil  # Import psutil to manage processes

from selenium import webdriver
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.chrome.service import Service

# Path to ChromeDriver (update if necessary)
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"  # Change if needed

# Path to allowed sites file
ALLOWED_SITES_FILE = "allowed_sites.txt"

# Regular expression pattern to capture OTP-like codes (6-digit numbers)
otp_pattern = r"\b\d{6}\b"

# Function to kill processes using a specific port (8080)
def kill_processes_using_port(port):
    for conn in psutil.net_connections(kind='inet'):  # Fetching network connections
        if conn.laddr.port == port:
            pid = conn.pid
            try:
                proc = psutil.Process(pid)
                proc.kill()  # Killing the process
                ctx.log.info(f"Killed process {pid} using port {port}")
            except psutil.NoSuchProcess:
                pass

# Create a simple tkinter window for displaying OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x150")

        self.otp_label = tk.Label(master, text="OTP will appear here", font=("Arial", 12))
        self.otp_label.pack(pady=20)

    def update_otp(self, otp):
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# OTP Interceptor that only captures OTPs from allowed sites
class OTPInterceptor:
    def __init__(self, allowed_sites):
        self.gui = None
        self.allowed_sites = allowed_sites

    def set_gui(self, gui):
        self.gui = gui

    def response(self, flow: mitmproxy.http.HTTPFlow):
        if any(site in flow.request.url for site in self.allowed_sites):
            if flow.response.content:
                content = flow.response.content.decode('utf-8', errors='ignore')
                otp_matches = re.findall(otp_pattern, content)
                if otp_matches:
                    otp = otp_matches[0]
                    if self.gui:
                        self.gui.update_otp(otp)
                        ctx.log.info(f"Captured OTP from {flow.request.url}: {otp}")

# Function to launch Chrome with Selenium
def launch_chrome():
    chrome_options = ChromeOptions()
    chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # Use mitmproxy as the proxy
    chrome_options.add_argument("--ignore-certificate-errors")  # Avoid SSL issues
    
    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    driver.get("https://example.com")  # Replace with a real site for OTP capture
    time.sleep(30)  # Adjust based on how long you need for interaction
    driver.quit()

# Function to start mitmproxy
async def start_mitmproxy(gui, allowed_sites):
    options = Options(listen_host='127.0.0.1', listen_port=8080)
    m = DumpMaster(options)
    interceptor = OTPInterceptor(allowed_sites)
    interceptor.set_gui(gui)
    m.addons.add(interceptor)
    await m.run()

# Function to load allowed websites
def load_allowed_sites():
    if not os.path.exists(ALLOWED_SITES_FILE):
        return []
    with open(ALLOWED_SITES_FILE, "r") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

# Function to configure allowed sites
def configure_allowed_sites():
    allowed_sites = load_allowed_sites()
    print("Current Allowed Websites:")
    for site in allowed_sites:
        print(f" - {site}")
    
    while True:
        choice = input("Do you want to add/remove a site? (add/remove/show/exit): ")
        if choice == "add":
            site = input("Enter the site URL (e.g., example.com): ")
            if site and site not in allowed_sites:
                allowed_sites.append(site)
        elif choice == "remove":
            site = input("Enter the site URL to remove: ")
            if site in allowed_sites:
                allowed_sites.remove(site)
        elif choice == "show":
            print("Allowed sites:", allowed_sites)
        elif choice == "exit":
            break
    
    with open(ALLOWED_SITES_FILE, "w") as f:
        for site in allowed_sites:
            f.write(site + "\n")
    print("Updated allowed sites.")

# Main function
def main():
    # Kill processes using port 8080 before starting the script
    kill_processes_using_port(8080)

    configure_allowed_sites()
    allowed_sites = load_allowed_sites()

    # Set up the GUI window
    root = tk.Tk()
    gui = OTPGUI(root)
    
    # Start mitmproxy in a separate thread
    mitm_thread = threading.Thread(target=lambda: asyncio.run(start_mitmproxy(gui, allowed_sites)))
    mitm_thread.start()

    # Start Selenium Chrome automation in a separate thread
    chrome_thread = threading.Thread(target=launch_chrome)
    chrome_thread.start()

    # Run the GUI loop
    root.mainloop()

if __name__ == "__main__":
    main()
