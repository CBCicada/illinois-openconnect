#!/usr/bin/env python3
"""UIUC VPN: browser SSO, IPv4 split routing, and up/down commands.

Usage:
    sudo python3 uiuc-vpn.py --check
    sudo python3 uiuc-vpn.py up
    sudo python3 uiuc-vpn.py down

Requires Linux, Python 3.9+, OpenConnect with external-browser SSO, iproute2,
and an interactive terminal for login. No chmod, pip packages, or SSH forwarding.
Debian/Ubuntu: sudo apt install python3 openconnect iproute2

Authenticate in your local browser, then paste its final localhost callback URL
at this script's prompt. PROXIED_CIDR=None uses server-advertised split routes;
a CIDR string restricts the VPN to that range instead. Default routes and DNS
are never replaced; IPv6 stays on the host network. Credentials are not stored.
Keep this file at a trusted, unchanged path while connected: it is also the hook.

UIUC docs: https://answers.uillinois.edu/illinois/47640
SSO protocol: https://gitlab.com/openconnect/openconnect/-/merge_requests/354
"""
import sys

if sys.platform != "linux" or sys.version_info < (3, 9):
    sys.exit("Requires Linux and Python 3.9 or newer.")

import argparse
import fcntl
import getpass
import http.client
import ipaddress
import json
import os
import select
import shlex
import shutil
import signal
import socket
import stat
import subprocess
from urllib.parse import urlsplit

VPN_SERVER = "https://vpn.illinois.edu/"
# modes: "1 Split Tunnel", "2 Tunnel All", "3 Split Tunnel Public IPs".
# Keep Split Tunnel selected; default routes are never accepted by this script.
VPN_PROFILE = "1 Split Tunnel"
# None = normal server split routes; a CIDR string = ONLY that IPv4 range.
# PROXIED_CIDR = "172.22.37.0/24"

TUN_DEVICE = "uiucvpn"
PID_FILE = "/run/uiuc-vpn.pid"
LOCK_FILE = "/run/uiuc-vpn.lock"
SELF = os.path.realpath(__file__)


def proxied_network():
    if PROXIED_CIDR is None:
        return None
    network = ipaddress.IPv4Network(PROXIED_CIDR)
    if network.prefixlen == 0:
        raise ValueError("PROXIED_CIDR must not be a default route")
    ssh = (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT", "")).split()
    if ssh and ipaddress.ip_address(ssh[0]) in network:
        raise ValueError("PROXIED_CIDR contains your SSH client; refusing to redirect SSH")
    return str(network)


def check_prerequisites(interactive):
    errors = []
    if os.geteuid() != 0:
        errors.append("Run as root (sudo).")
    try:
        proxied_network()
    except ValueError as error:
        errors.append(str(error))
    tools = {name: shutil.which(name) for name in ("openconnect", "ip")}
    for name, path in tools.items():
        if path is None:
            errors.append("Missing executable: " + name)
    if tools["openconnect"]:
        help_result = subprocess.run([tools["openconnect"], "--help"],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, check=False)
        if "--external-browser" not in help_result.stdout:
            errors.append("OpenConnect must support --external-browser SSO.")
    try:
        if not stat.S_ISCHR(os.stat("/dev/net/tun").st_mode):
            errors.append("/dev/net/tun must be a TUN character device.")
        else:
            os.close(os.open("/dev/net/tun", os.O_RDWR))
    except OSError:
        errors.append("Cannot open /dev/net/tun; enable Linux TUN and grant access.")
    with open("/proc/self/status") as status:
        capabilities = next(line.split()[1] for line in status if line.startswith("CapEff:"))
    if not int(capabilities, 16) & (1 << 12):
        errors.append("CAP_NET_ADMIN is required to configure the tunnel.")
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as listener:
            listener.bind(("::1", 0))
    except OSError:
        errors.append("IPv6 loopback (::1) is required for OpenConnect's SSO callback.")
    if interactive:
        try:
            os.close(os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY))
        except OSError:
            errors.append("An interactive terminal is required (use ssh -t when necessary).")
    if errors:
        raise RuntimeError("Prerequisite check failed:\n- " + "\n- ".join(errors)
                           + "\nDebian/Ubuntu: sudo apt install python3 openconnect iproute2")
    return tools


def split_networks():
    configured = proxied_network()
    if configured is not None:
        networks = [ipaddress.IPv4Network(configured)]
    else:
        count = int(os.environ.get("CISCO_SPLIT_INC", "0"))
        if count <= 0:
            raise ValueError("VPN did not advertise split routes; refusing a default-route fallback")
        networks = []
        for index in range(count):
            key = "CISCO_SPLIT_INC_" + str(index)
            mask = os.environ.get(key + "_MASKLEN") or os.environ[key + "_MASK"]
            networks.append(ipaddress.IPv4Network(os.environ[key + "_ADDR"] + "/" + mask,
                                                 strict=False))
    if any(network.prefixlen == 0 for network in networks):
        raise ValueError("Refusing a VPN default route")
    exclusions = []
    if configured is None:
        for index in range(int(os.environ.get("CISCO_SPLIT_EXC", "0"))):
            key = "CISCO_SPLIT_EXC_" + str(index)
            mask = os.environ.get(key + "_MASKLEN") or os.environ[key + "_MASK"]
            exclusions.append(ipaddress.IPv4Network(os.environ[key + "_ADDR"] + "/" + mask,
                                                   strict=False))
        # Preserve directly connected host networks even when subtracting a
        # protected peer would otherwise create more-specific campus routes.
        local_routes = subprocess.check_output(
            [shutil.which("ip"), "-j", "-4", "route", "show", "scope", "link"], text=True)
        for route in json.loads(local_routes):
            if route.get("dev") != TUN_DEVICE:
                exclusions.append(ipaddress.IPv4Network(route["dst"], strict=False))
    # Campus split routes can include the VPN server itself. Keep its transport
    # and the SSH peer on their existing host routes, never recursively in VPN.
    ssh = (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_CLIENT", "")).split()
    for value in [os.environ.get("VPNGATEWAY"), ssh[0] if ssh else None]:
        if value and ipaddress.ip_address(value).version == 4:
            exclusions.append(ipaddress.IPv4Network(value + "/32"))
    for excluded in exclusions:
        remaining = []
        for network in networks:
            if network.subnet_of(excluded):
                continue
            if excluded.subnet_of(network):
                remaining.extend(network.address_exclude(excluded))
            else:
                remaining.append(network)
        networks = remaining
    return list(ipaddress.collapse_addresses(networks))


def configure_routes():
    if os.environ.get("TUNDEV") != TUN_DEVICE:
        raise ValueError("Refusing to configure any interface except " + TUN_DEVICE)
    reason = os.environ.get("reason", "")
    if reason in ("pre-init", "attempt-reconnect"):
        return
    ip = shutil.which("ip")
    if ip is None:
        raise RuntimeError("Missing executable: ip (install iproute2)")
    if reason == "disconnect":
        subprocess.run([ip, "-4", "route", "flush", "dev", TUN_DEVICE], check=True)
        subprocess.run([ip, "link", "set", "dev", TUN_DEVICE, "down"], check=True)
    elif reason in ("connect", "reconnect"):
        networks = split_networks()
        if not networks:
            raise ValueError("No VPN destinations remain after split-route exclusions")
        address = str(ipaddress.IPv4Address(os.environ["INTERNAL_IP4_ADDRESS"]))
        mtu = str(int(os.environ.get("INTERNAL_IP4_MTU") or "1406"))
        commands = [
            ["link", "set", "dev", TUN_DEVICE, "mtu", mtu, "up"],
            ["-4", "route", "flush", "dev", TUN_DEVICE],
            ["-4", "address", "flush", "dev", TUN_DEVICE, "scope", "global"],
            # A /32 + noprefixroute prevents an additional campus subnet route.
            ["-4", "address", "add", address + "/32", "dev", TUN_DEVICE, "noprefixroute"],
        ]
        commands.extend(
            ["-4", "route", "add", str(network), "dev", TUN_DEVICE, "src", address,
             "proto", "static"] for network in networks
        )
        try:
            for command in commands:
                subprocess.run([ip] + command, check=True)
        except subprocess.CalledProcessError:
            subprocess.run([ip, "-4", "route", "flush", "dev", TUN_DEVICE], check=False)
            subprocess.run([ip, "link", "set", "dev", TUN_DEVICE, "down"], check=False)
            raise
    else:
        raise ValueError("Unsupported VPN hook reason: " + reason)


def browser_login(login_url):
    with open("/dev/tty", "w") as terminal:
        print("\n=== UIUC VPN — browser authentication ===", file=terminal)
        print("Click on this link to auth:\n\n" + login_url, file=terminal)
        print("\nUse your local browser and hardware key.", file=terminal)
        print("After auth, copy the final http://localhost:29786/api/sso/... link.",
              file=terminal)
        print("A browser connection-refused error is expected. No SSH forwarding.",
              file=terminal, flush=True)
        callback = getpass.getpass(
            "\nAfter auth, paste your link here (hidden): ", stream=terminal).strip()
    url = urlsplit(callback)
    if (url.scheme != "http" or url.hostname not in ("localhost", "127.0.0.1", "::1")
            or url.port != 29786 or url.username is not None or url.password is not None
            or not url.path.startswith("/api/sso/")
            or len(url.path) == len("/api/sso/") or url.fragment
            or any(ord(char) <= 32 or ord(char) >= 127 for char in callback)):
        raise ValueError("Expected the complete localhost SSO callback URL")
    target = url.path + ("?" + url.query if url.query else "")
    # Only contact OpenConnect's loopback listener; never follow ?return= redirects.
    connection = http.client.HTTPConnection("::1", 29786, timeout=15)
    try:
        connection.request("GET", target)
        response = connection.getresponse()
        response.read()
        if response.status not in (200, 302):
            raise ValueError("OpenConnect rejected the callback URL")
    finally:
        connection.close()
    scope = PROXIED_CIDR if PROXIED_CIDR is not None else "server split routes"
    print("Callback submitted. OpenConnect will now authenticate and configure "
          + scope + ".", file=sys.stderr, flush=True)


def connect():
    tools = check_prerequisites(interactive=True)
    lock = os.open(LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise RuntimeError("UIUC VPN is already running or being authenticated.") from None
    if subprocess.run([tools["ip"], "link", "show", "dev", TUN_DEVICE],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                      check=False).returncode == 0:
        raise RuntimeError(TUN_DEVICE + " already exists; refusing a second connection.")
    os.set_inheritable(lock, True)
    os.environ["UIUC_VPN_PID"] = str(os.getpid())
    # OpenConnect accepts only an executable path for its browser hook. An
    # inherited in-memory shell entrypoint lets the published Python file stay
    # non-executable, without generating any helper files on disk.
    browser = os.memfd_create("uiuc-vpn-browser", flags=0)
    entrypoint = "#!/bin/sh\nexec " + shlex.join([sys.executable, SELF, "--browser"]) + ' "$@"\n'
    os.write(browser, entrypoint.encode())
    os.set_inheritable(browser, True)
    os.execv(tools["openconnect"], [
        tools["openconnect"], "--protocol=anyconnect", "--useragent=AnyConnect",
        "--authgroup=" + VPN_PROFILE, "--external-browser=/proc/self/fd/" + str(browser), "--no-proxy",
        "--disable-ipv6", "--interface=" + TUN_DEVICE,
        "--script=" + shlex.join([sys.executable, SELF, "--route"]), "--background", "--syslog",
        "--pid-file=" + PID_FILE, VPN_SERVER,
    ])


def disconnect():
    if os.geteuid() != 0:
        raise RuntimeError("Run as root (sudo).")
    try:
        with open(PID_FILE) as state:
            recorded = state.read().strip()
    except FileNotFoundError:
        print("VPN is not running.")
        return
    pid = int(recorded)
    if pid <= 1:
        raise ValueError("Invalid VPN PID; refusing to signal it")
    descriptor = None
    try:
        descriptor = os.pidfd_open(pid)
        with open("/proc/" + str(pid) + "/cmdline", "rb") as command:
            args = command.read().decode().rstrip("\0").split("\0")
        if (not args or os.path.basename(args[0]) != "openconnect"
                or "--interface=" + TUN_DEVICE not in args
                or "--pid-file=" + PID_FILE not in args):
            raise RuntimeError("PID does not identify this VPN; refusing to signal another process")
        signal.pidfd_send_signal(descriptor, signal.SIGINT)
        if not select.select([descriptor], [], [], 15)[0]:
            raise RuntimeError("VPN is still shutting down; no force-kill was attempted")
    except (ProcessLookupError, FileNotFoundError):
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)
    try:
        with open(PID_FILE) as state:
            unchanged = state.read().strip() == recorded
        if unchanged:
            os.unlink(PID_FILE)
    except FileNotFoundError:
        pass
    print("VPN disconnected.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", nargs="?", choices=("up", "down"))
    parser.add_argument("--check", action="store_true", help="check prerequisites without connecting")
    parser.add_argument("--route", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--browser", metavar="URL", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.browser:
        try:
            browser_login(args.browser)
            return 0
        except (EOFError, KeyboardInterrupt):
            print("\nVPN login cancelled.", file=sys.stderr)
            result = 130
        except (OSError, ValueError, http.client.HTTPException) as error:
            # Exception text can contain the secret callback; never echo it.
            print("VPN callback failed (" + type(error).__name__ + "); rerun this script.",
                  file=sys.stderr)
            result = 1
        parent = os.getppid()
        if os.environ.get("UIUC_VPN_PID") == str(parent):
            try:
                os.kill(parent, signal.SIGINT)
            except ProcessLookupError:
                pass
        return result
    if args.route:
        configure_routes()
    elif args.command == "down":
        disconnect()
    elif args.check:
        check_prerequisites(interactive=False)
        print("Prerequisites OK. Login additionally needs an interactive terminal.")
    elif args.command == "up":
        connect()
    else:
        parser.error("choose up or down, or use --check")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
    except KeyboardInterrupt:
        sys.exit(130)
