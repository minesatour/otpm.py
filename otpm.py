import json
import re
import sqlite3
import threading
import time
import tkinter as tk
from tkinter import messagebox, simpledialog
from selenium import webdriver
from selenium.webdriver.chrome.service import Service  # Ensure this is imported
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium_stealth import stealth

# CONFIGURATIONS
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
OTP_STORAGE_FILE = "captured_otps.db"
OTP_PATTERN = r"\b\d{6}\b"  # Adjust this pattern based on the OTP format
PROXY_LIST = ["http://proxy1:port", "http://proxy2:port"]  # Add real proxies here
USE_PROXY = False  # Default setting
ALLOWED_SITES_FILE = "allowed_sites.txt"

# SETUP DATABASE
def setup_database():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY, otp TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.commit()
    conn.close()

# STORE OTP IN DATABASE
def store_otp(otp):
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO otps (otp) VALUES (?)", (otp,))
    conn.commit()
    conn.close()

# GUI TO DISPLAY OTP
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

# CHROME DRIVER SETUP
def launch_chrome(target_url, use_proxy):
    chrome_options = ChromeOptions()
    if use_proxy and PROXY_LIST:
        proxy = PROXY_LIST[0]  # Simple proxy rotation
        print(f"🆓 Using proxy: {proxy}")
        chrome_options.add_argument(f"--proxy-server={proxy}")
    
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--start-maximized")  # Start maximized to see the browser

    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32", webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
    driver.get(target_url)
    return driver

# Load allowed sites from a file
def load_allowed_sites():
    try:
        with open(ALLOWED_SITES_FILE, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("Allowed sites file not found. Please create 'allowed_sites.txt'.")
        return []

# OTP INTERCEPTION
def intercept_otp(driver, gui, allowed_sites):
    while True:
        time.sleep(1)  # Polling interval
        current_url = driver.current_url
        if any(site in current_url for site in allowed_sites):
            page_source = driver.page_source
            otp_matches = re.findall(OTP_PATTERN, page_source)
            if otp_matches:
                otp = otp_matches[0]
                gui.update_otp(otp)
                print(f"✅ Captured OTP: {otp}")

# STARTUP MENU
def menu():
    global USE_PROXY
    print("1. Run with Proxy")
    print("2. Run without Proxy")
    choice = input("Choose an option: ")
    if choice == "1":
        USE_PROXY = True
    elif choice == "2":
        USE_PROXY = False
    else:
        print("❌ Invalid choice. Defaulting to no proxy.")
        USE_PROXY = False

# MAIN FUNCTION
def main():
    setup_database()
    menu()
    
    root = tk.Tk()
    gui = OTPGUI(root)
    
    allowed_sites = load_allowed_sites()
    if not allowed_sites:
        messagebox.showerror("Error", "No allowed sites found. Please add sites to 'allowed_sites.txt'.")
        return
    
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")
    if target_url not in allowed_sites:
        messagebox.showerror("Error", "The entered URL is not in the allowed sites list.")
        return
    
    messagebox.showinfo("Action Required", "🚀 Please log in and request the OTP.")
    
    driver = launch_chrome(target_url, USE_PROXY)
    
    # Run OTP interception in a separate thread
    intercept_thread = threading.Thread(target=intercept_otp, args=(driver, gui, allowed_sites))
    intercept_thread.daemon = True
    intercept_thread.start()
    
    root.mainloop()
    driver.quit()

if __name__ == "__main__":
    main()
