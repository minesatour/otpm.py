import asyncio
import mitmproxy
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options as ChromeOptions
from webdriver_manager.chrome import ChromeDriverManager
import time
import threading

class OTPInterceptor:
    def __init__(self):
        self.driver = None
        self.mitmproxy_ready = threading.Event()  # Ensures mitmproxy is ready before launching Chrome

    def start_mitmproxy(self):
        """Starts mitmproxy with an explicitly created event loop."""
        loop = asyncio.new_event_loop()  # ✅ Create a new event loop inside the thread
        asyncio.set_event_loop(loop)  # ✅ Set it as the running event loop

        options = Options(listen_host='127.0.0.1', listen_port=8080)
        m = DumpMaster(options, with_termlog=False, with_dumper=False)

        self.mitmproxy_ready.set()  # ✅ Notify that mitmproxy is running

        try:
            loop.run_until_complete(m.run())  # ✅ Ensure mitmproxy runs within the loop
        except KeyboardInterrupt:
            m.shutdown()
        except Exception as e:
            print(f"Mitmproxy Error: {e}")

    def launch_chrome(self):
        """Launches Chrome after ensuring mitmproxy is running."""
        self.mitmproxy_ready.wait()  # ✅ Wait for mitmproxy to start

        chrome_options = ChromeOptions()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--proxy-server=http://127.0.0.1:8080")  # ✅ Route through mitmproxy

        service = Service(ChromeDriverManager().install())
        self.driver = webdriver.Chrome(service=service, options=chrome_options)

        try:
            self.driver.get("http://example.com")  # ✅ Replace with actual OTP-receiving website
            time.sleep(10)  # ✅ Adjust based on OTP retrieval timing
        finally:
            self.driver.quit()

    def response(self, flow: mitmproxy.http.HTTPFlow):
        """Intercepts and logs OTP-related responses."""
        if "otp" in flow.request.pretty_url:
            print(f"Intercepted OTP response: {flow.response.content.decode('utf-8')}")

def start_mitmproxy_thread(interceptor):
    """Runs mitmproxy in a separate thread with its own event loop."""
    interceptor.start_mitmproxy()

def launch_chrome_thread(interceptor):
    """Runs Chrome in a separate thread after mitmproxy starts."""
    interceptor.launch_chrome()

if __name__ == "__main__":
    interceptor = OTPInterceptor()

    # ✅ Start mitmproxy in a separate thread
    mitmproxy_thread = threading.Thread(target=start_mitmproxy_thread, args=(interceptor,), daemon=True)
    mitmproxy_thread.start()

    # ✅ Start the browser automation in a separate thread
    chrome_thread = threading.Thread(target=launch_chrome_thread, args=(interceptor,), daemon=True)
    chrome_thread.start()

    # ✅ Join threads so the program waits for them
    mitmproxy_thread.join()
    chrome_thread.join()
