#!/usr/bin/env python
import argparse
import socket
import ssl
import sys
from datetime import datetime, timedelta

import OpenSSL

try:
    import requests
except ImportError:
    print("Lib requests is required to run this program.")
    print("run: pip install requests")
    sys.exit(1)

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
    COLORAMA_ENABLED = True
except ImportError:
    COLORAMA_ENABLED = False
    print("to add colors to the output install colorama")
    print("run: pip install colorama")

# Number of days before the date is flagged has 'soon' (yellow)
CERT_EXPIRY_LIMIT = 15

# Explicitly flag (appear red) cert issuers
BAD_CERT_ISSUERS = [
    "(STAGING) Let's Encrypt",
    "Kubernetes Ingress Controller Fake Certificate",
]

# Explicitly authorize (appear green) cert issuers
GOOD_CERT_ISSUERS = [
    "Let's Encrypt",
    "Google Trust Services LLC",
]


def read_hosts(file):
    with open(file, "r") as f:
        host_list = []
        for line in f:
            if line.startswith("#") or line == "\n":
                continue
            host_list.append(line.rstrip("\n"))
    return host_list


def print_start_message(host_list):
    len_hosts = len(host_list)
    print("Checking SSL certificates for {} hosts.".format(len_hosts))
    if len(host_list) > 1:
        print("From '{}' to '{}'.".format(host_list[0], host_list[-1]))
    print()


def get_certificate(host, port=443, timeout=10):
    """Return an SSL certificates in the x509 format."""
    cert = ssl.get_server_certificate((host, 443))
    x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    return x509


def get_not_after_from_x509(x509):
    return datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")


def get_issuer_from_x509(x509):
    return x509.get_issuer().get_components()


def color_cert_date(cert_expiry_date):
    if datetime.now() > cert_expiry_date:
        return Fore.RED
    elif (datetime.now() + timedelta(days=CERT_EXPIRY_LIMIT)) > cert_expiry_date:
        return Fore.YELLOW
    return Fore.GREEN


def color_cert_issuer(cert_issuer):
    if cert_issuer in BAD_CERT_ISSUERS:
        return Fore.RED
    elif cert_issuer in GOOD_CERT_ISSUERS:
        return Fore.GREEN
    return None


def get_host_status_code(host):
    try:
        status_code = requests.get(host).status_code
    except requests.exceptions.SSLError:
        status_code = "SSL ERROR"
    except requests.exceptions.Timeout:
        status_code = "TIMEOUT"
    except Exception as e:
        status_code = e
    return status_code


def color_status_code(status_code):
    if type(status_code) == str:
        return Fore.RED
    elif 100 <= status_code < 200:
        return Fore.YELLOW
    elif 200 <= status_code < 300:
        return Fore.GREEN
    elif 300 <= status_code < 400:
        return Fore.YELLOW
    elif 400 <= status_code < 500:
        return Fore.YELLOW
    elif 500 <= status_code:
        return Fore.RED
    return Fore.WHITE


def print_host_status_code(host, message=None, spacing=12):
    host = host.replace("http://", "")
    host = host.replace("https://", "")

    if message is None:
        message = host

    https_status_code = get_host_status_code(f"https://{host}")

    x509 = get_certificate(host)
    cert_expiry_date = get_not_after_from_x509(x509)
    cert_issuer = get_issuer_from_x509(x509)[1][1].decode()

    https_text = f"{str(https_status_code):{spacing}}"
    cert_date_text = cert_expiry_date.date() if cert_expiry_date else "-"
    cert_date_text = f"{str(cert_date_text):{spacing}}"
    cert_issuer_text = f"{str(cert_issuer):{spacing + 11}}"

    if COLORAMA_ENABLED:
        https_text = f"{Fore.RESET}{color_status_code(https_status_code)}{https_text}"
        cert_date_text = (
            f"{Fore.RESET}{color_cert_date(cert_expiry_date)}{cert_date_text}"
        )
        cert_issuer_text = (
            f"{Fore.RESET}{color_cert_issuer(cert_issuer)}{cert_issuer_text}"
        )

    print(f"{https_text} {cert_date_text} {cert_issuer_text} {message}")


def print_host_list(host_list):
    SPACING = 12
    print(
        f"{'HTTP code':{SPACING}} {'SSL expiry':{SPACING}} {'Issuer':{SPACING + 11}} host"
    )
    for host in host_list:
        print_host_status_code(host, spacing=SPACING)


def main():
    global HOST_LIST, API_HOST_LIST, SITES_HOST_LIST

    parser = argparse.ArgumentParser(
        prog="certval",
        description="%(prog)s CLI tool to test host SSL certificates validity.",
    )
    parser.add_argument(
        "-f",
        "--file",
        help="A file containing a list of hosts to check, separated by new lines.",
        default="hosts.txt",
    )

    args = parser.parse_args()

    try:
        host_list = read_hosts(args.file)
    except FileNotFoundError:
        print("File '{}' not found.".format(args.file))
        sys.exit(1)

    if len(host_list) == 0:
        print("No hosts to check found in {}.".format(args.file))
        sys.exit(1)

    print_start_message(host_list)
    print_host_list(host_list)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(1)
