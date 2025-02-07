import json
import re
import sqlite3
import threading
import time
import random
import tkinter as tk
from tkinter import messagebox, simpledialog
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium_stealth import stealth
from PIL import Image
import pytesseract

# CONFIGURATIONS
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
OTP_STORAGE_FILE = "captured_otps.db"
ALLOWED_SITES_FILE = "allowed_sites.txt"
OTP_EXPIRY_HOURS = 24  # Purge OTPs older than this value

# OTP Detection Patterns
OTP_PATTERN = r"\b\d{6}\b"  # Adjust this pattern based on OTP format
OTP_KEYWORDS = [
    "Your OTP is", "Enter this code", "Verification code",
    "Security code", "2FA code", "One-time password",
    "Login code", "Confirm your identity", "Authenticate with this code"
]

# User-Agent list for rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; Pixel 3 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

# Proxy List (Replace with working proxies)
PROXY_LIST = ["proxy1:port", "proxy2:port"]  # Add your proxies here

# SETUP DATABASE
def setup_database():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS otps (
            id INTEGER PRIMARY KEY, 
            otp TEXT, 
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

# STORE OTP IN DATABASE
def store_otp(otp):
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO otps (otp) VALUES (?)", (otp,))
    conn.commit()
    conn.close()

# CLEANUP OLD OTPs
def cleanup_otps():
    conn = sqlite3.connect(OTP_STORAGE_FILE)
    c = conn.cursor()
    c.execute(f"DELETE FROM otps WHERE timestamp < datetime('now', '-{OTP_EXPIRY_HOURS} hours')")
    conn.commit()
    conn.close()

# GUI TO DISPLAY OTP
class OTPGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Captured OTP")
        self.master.geometry("300x200")
        self.otp_label = tk.Label(master, text="Waiting for OTP...", font=("Arial", 12))
        self.otp_label.pack(pady=20)

        self.capture_button = tk.Button(master, text="Start OTP Capture", command=self.start_capturing)
        self.capture_button.pack(pady=10)

        self.capturing = False

    def start_capturing(self):
        self.capturing = True
        self.otp_label.config(text="Capturing OTP...")

    def update_otp(self, otp):
        store_otp(otp)
        self.otp_label.config(text=f"Captured OTP: {otp}")
        messagebox.showinfo("OTP Captured", f"OTP: {otp}")

# PROXY HANDLING
def get_random_proxy():
    return random.choice(PROXY_LIST)

# CHROME DRIVER SETUP
def launch_chrome(target_url, use_proxy=False):
    chrome_options = ChromeOptions()
    chrome_options.add_argument(f"user-agent={random.choice(USER_AGENTS)}")
    chrome_options.add_argument("--ignore-certificate-errors")
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--start-maximized")

    if use_proxy:
        proxy = get_random_proxy()
        chrome_options.add_argument(f"--proxy-server={proxy}")
        print(f"🌐 Using Proxy: {proxy}")

    driver = webdriver.Chrome(service=Service(CHROMEDRIVER_PATH), options=chrome_options)
    stealth(driver, languages=["en-US", "en"], vendor="Google Inc.", platform="Win32",
            webgl_vendor="Intel Inc.", renderer="Intel Iris OpenGL Engine", fix_hairline=True)
    driver.get(target_url)
    return driver

# LOAD ALLOWED SITES
def load_allowed_sites():
    try:
        with open(ALLOWED_SITES_FILE, 'r') as file:
            return [line.strip() for line in file if line.strip()]
    except FileNotFoundError:
        print("Allowed sites file not found. Please create 'allowed_sites.txt'.")
        return []

# OTP INTERCEPTION (SMART DETECTION)
def intercept_otp(driver, gui, allowed_sites):
    otp_captured = False
    while not otp_captured:
        time.sleep(random.uniform(2, 5))
        if gui.capturing:
            try:
                current_url = driver.current_url
                if any(site in current_url for site in allowed_sites):
                    page_source = driver.page_source
                    otp_candidates = re.findall(OTP_PATTERN, page_source)

                    for otp in otp_candidates:
                        if any(keyword in page_source for keyword in OTP_KEYWORDS):
                            otp_captured = True
                            gui.update_otp(otp)
                            print(f"✅ Captured OTP: {otp}")
                            return
            except Exception as e:
                print(f"⚠ OTP Interception Error: {e}")

# OCR-BASED OTP DETECTION
def extract_otp_from_image(image_path):
    text = pytesseract.image_to_string(Image.open(image_path))
    otp_candidates = re.findall(OTP_PATTERN, text)
    if otp_candidates:
        print(f"🖼 OCR Captured OTP: {otp_candidates[0]}")
        return otp_candidates[0]
    return None

# JavaScript-Based OTP Monitoring
def monitor_otp_live(driver):
    js_script = """
    setInterval(() => {
        let otp_elements = document.body.innerText.match(/\b\d{6}\b/g);
        if (otp_elements) {
            console.log('OTP:', otp_elements[0]);
        }
    }, 1000);
    """
    driver.execute_script(js_script)

# MENU
def menu():
    print("1. Run with Proxy")
    print("2. Run without Proxy")
    choice = input("Choose an option: ")
    return choice == "1"

# MAIN FUNCTION
def main():
    setup_database()
    cleanup_otps()
    use_proxy = menu()

    root = tk.Tk()
    gui = OTPGUI(root)

    allowed_sites = load_allowed_sites()
    target_url = simpledialog.askstring("Target Website", "Enter the OTP website URL:")

    driver = launch_chrome(target_url, use_proxy)
    monitor_otp_live(driver)

    intercept_thread = threading.Thread(target=intercept_otp, args=(driver, gui, allowed_sites))
    intercept_thread.daemon = True
    intercept_thread.start()

    root.mainloop()
    driver.quit()

if __name__ == "__main__":
    main()
