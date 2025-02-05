import os
import signal
import subprocess
import time
import shutil
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import psutil

# Define paths
CHROMEDRIVER_PATH = "/usr/bin/chromedriver"
PROXY_PORT = 8080  # Default port for mitmproxy

def kill_process_using_port(port):
    """Kills any process currently using the specified port."""
    try:
        result = subprocess.run(["lsof", "-i", f":{port}"], capture_output=True, text=True)
        lines = result.stdout.split("\n")[1:]  # Ignore the header
        for line in lines:
            if line.strip():
                parts = line.split()
                pid = int(parts[1])  # Process ID
                os.kill(pid, signal.SIGKILL)
                print(f"Killed process {pid} using port {port}")
    except Exception as e:
        print(f"No process found using port {port} or error occurred: {e}")

def find_free_port(start_port=8080, max_attempts=10):
    """Finds an available port starting from a given port."""
    for i in range(max_attempts):
        port = start_port + i
        if not is_port_in_use(port):
            return port
    raise Exception("No free ports found!")

def is_port_in_use(port):
    """Checks if a port is in use."""
    with os.popen(f"lsof -i :{port}") as proc:
        return bool(proc.read().strip())

def launch_chrome():
    """Launches Chrome with predefined options."""
    global PROXY_PORT  # Declare global variable here after initialization

    print("[*] Killing processes on port 8080...")
    kill_process_using_port(PROXY_PORT)

    # Check if default port is in use and find an alternative
    if is_port_in_use(PROXY_PORT):
        PROXY_PORT = find_free_port()

    print(f"[*] Using port {PROXY_PORT} for mitmproxy")

    # Set up Chrome options
    chrome_options = Options()
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    
    # Explicitly define ChromeDriver path
    service = Service(CHROMEDRIVER_PATH)

    # Launch Chrome
    try:
        driver = webdriver.Chrome(service=service, options=chrome_options)
        print("[*] Chrome launched successfully.")
        return driver
    except Exception as e:
        print(f"[ERROR] Failed to launch Chrome: {e}")
        return None

def main():
    print("[*] Starting script...")

    # Kill any lingering processes using key ports
    kill_process_using_port(PROXY_PORT)

    # Launch Chrome
    driver = launch_chrome()
    if driver:
        driver.get("https://example.com")  # Test if Chrome works
        print("[*] Successfully opened example.com")
        time.sleep(5)  # Keep browser open for testing
        driver.quit()

if __name__ == "__main__":
    main()
