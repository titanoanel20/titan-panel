#!/usr/bin/env python3
"""Download Xray-core for local testing (Linux x64)."""
import os
import urllib.request
import zipfile

URL = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
DEST = "/usr/local/bin"

def main():
    os.makedirs(DEST, exist_ok=True)
    print("Downloading Xray-core …")
    zip_path = "/tmp/xray.zip"
    urllib.request.urlretrieve(URL, zip_path)
    with zipfile.ZipFile(zip_path) as z:
        z.extractall(DEST)
    os.chmod(os.path.join(DEST, "xray"), 0o755)
    print("Xray installed at", os.path.join(DEST, "xray"))

if __name__ == "__main__":
    main()
