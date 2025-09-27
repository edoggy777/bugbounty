Sometimes a clean restart helps:
1. Stop mitmproxy (Ctrl+C)
2. Clear proxy on device:
adb shell settings delete global http_proxy

3. Restart mitmproxy:
mitmproxy

4. Re-set proxy:
adb shell settings put global http_proxy YOUR_IP:8080

5. Test browser traffic

Start with default settings first
mitmproxy

Should show: "Proxy server listening at http://*:8080"
Keep this terminal window open

Method A: ADB (if device is connected via USB)
adb devices  # Verify device connected
adb shell settings put global http_proxy YOUR_IP:8080

Method B: Manual WiFi Settings
On device: Settings → WiFi → Long press your network → Modify
Advanced → Proxy → Manual
Host: YOUR_IP (e.g., 192.168.1.100)
Port: 8080

On Android device browser, visit:
http://mitm.it

Download "Android" certificate
Install it: Settings → Security → Install certificates → CA certificate
Give it a name like "mitmproxy-test"

Only do this after basic setup works
Generate custom certificate
openssl req -x509 -newkey rsa:2048 -keyout custom.key -out custom.crt -days 365 -nodes \
  -subj "/CN=fake-api.com"

Combine for mitmproxy
cat custom.key custom.crt > custom.pem

Stop mitmproxy (Ctrl+C) and restart with custom cert
mitmproxy --cert custom.pem

Install On Device::

Convert to Android format
openssl x509 -outform DER -in custom.crt -out custom.der

Push to device
adb push custom.der /sdcard/Download/custom.crt

Install on device:
Settings → Security → Install certificates → CA certificate
Select custom.crt from Downloads

Test app again with your custom certificate
If app still works → accepts any valid certificate (vulnerable)
If app fails → may have proper certificate pinning

