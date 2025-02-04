import asyncio
import mitmproxy
from mitmproxy.tools.dump import DumpMaster
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
import time
import threading

class OTPInterceptor:
    def __init__(self):
        self.driver = None

    def start_mitmproxy(self):
        # Setup mitmproxy options
        options = mitmproxy.options.Options(listen_host='127.0.0.1', listen_port=8080)
        m = DumpMaster(options)

        # Create asyncio event loop and run mitmproxy
        loop = asyncio.get_event_loop()
        loop.run_until_complete(m.run())  # Ensure it runs the mitmproxy master

    def launch_chrome(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")  # Run in headless mode (without opening browser window)
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # Mitmproxy listens on this port

        chromedriver_path = "/path/to/chromedriver"  # Update with correct chromedriver path
        service = Service(chromedriver_path)
        self.driver = webdriver.Chrome(service=service, options=chrome_options)

        self.driver.get("http://example.com")  # Use the URL you want to test with

        # Wait for OTP or login process to happen
        time.sleep(10)  # Adjust based on your use case
        self.driver.quit()

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # Intercept and log the OTP response (or any relevant response you want to capture)
        if "otp" in flow.request.pretty_url:
            print(f"Intercepted OTP response: {flow.response.content.decode('utf-8')}")


def start_mitmproxy_thread():
    interceptor = OTPInterceptor()
    interceptor.start_mitmproxy()


def launch_chrome_thread():
    interceptor = OTPInterceptor()
    interceptor.launch_chrome()


if __name__ == "__main__":
    # Start mitmproxy in a separate thread
    mitmproxy_thread = threading.Thread(target=start_mitmproxy_thread)
    mitmproxy_thread.start()

    # Start the browser automation in a separate thread
    chrome_thread = threading.Thread(target=launch_chrome_thread)
    chrome_thread.start()

    # Join threads so the main program waits for them to finish
    mitmproxy_thread.join()
    chrome_thread.join()
