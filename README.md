# Illinois OpenConnect

Python script for the UIUC VPN, with browser SSO and split routing.

Requires Python 3.9+, OpenConnect, iproute2, root, and TUN support.

```sh
# Debian/Ubuntu prerequisites
sudo apt install python3 openconnect iproute2

sudo python3 uiuc-vpn.py --check
sudo python3 uiuc-vpn.py up
sudo python3 uiuc-vpn.py down
```

For `up`, open the printed login link in your local browser, authenticate, then paste the final localhost URL into the script's prompt.

Define `PROXIED_CIDR = None` in the script for normal campus split routes, or set it to a CIDR string to tunnel only that range. This is to circumvent the case where the range being tunneled overlaps with the uplink.
