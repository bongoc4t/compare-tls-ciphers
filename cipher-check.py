#this script is to compare what TLS cipher suite is using the domain we are targeting.

import socket
import ssl
import sys

LOW = [
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_AES_256_GCM_SHA384",
]

MEDIUM = [
    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
]

HIGH = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
]

# Mapping OpenSSL cipher suite names to IANA names
OPENSSL_TO_IANA = {
    "AES128-SHA": "TLS_RSA_WITH_AES_128_CBC_SHA",
    "AES128-GCM-SHA256": "TLS_RSA_WITH_AES_128_GCM_SHA256",
    "AES256-SHA": "TLS_RSA_WITH_AES_256_CBC_SHA",
    "AES256-GCM-SHA384": "TLS_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-SHA": "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    "ECDHE-ECDSA-AES256-SHA": "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    "ECDHE-RSA-AES128-SHA": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    "ECDHE-RSA-AES256-SHA": "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    "AES128-GCM-SHA256": "TLS_AES_128_GCM_SHA256",
    "AES256-GCM-SHA384": "TLS_AES_256_GCM_SHA384",
    "ECDHE-ECDSA-AES128-GCM-SHA256": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-ECDSA-AES256-GCM-SHA384": "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-AES128-GCM-SHA256": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384": "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305": "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "ECDHE-ECDSA-CHACHA20-POLY1305": "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

def ip_to_domain(ip):
    try:
        domain, _, _ = socket.gethostbyaddr(ip)
        return domain
    except socket.herror as e:
        return None

def check_cipher_level(domain, port=443):
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET), server_hostname=domain
    )

    try:
        conn.connect((domain, port))
        cipher_openssl = conn.cipher()[0]
        cipher_iana = OPENSSL_TO_IANA.get(cipher_openssl, cipher_openssl)

        if cipher_iana in LOW:
            return "Low", True, cipher_iana
        elif cipher_iana in MEDIUM:
            return "Medium", True, cipher_iana
        elif cipher_iana in HIGH:
            return "High", True, cipher_iana
        else:
            return "Unknown", False, cipher_iana

    except ssl.SSLError as e:
        if "CERTIFICATE_VERIFY_FAILED" in str(e):
            return "Error: Certificate verification failed, certificate has expired.", False, None
        else:
            return f"SSL error: {e}", False, None
    except Exception as e:
        return f"Error: {e}", False, None
    finally:
        conn.close()

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python check_tls_cipher.py <domain_or_ip>")
        sys.exit(1)

    input_value = sys.argv[1]

    # Check if the input is an IP address
    try:
        socket.inet_aton(input_value)
        is_ip = True
    except socket.error:
        is_ip = False

    if is_ip:
        domain = ip_to_domain(input_value)
        if not domain:
            print(f"Error: Unable to resolve the domain for IP address {input_value}")
            sys.exit(1)
    else:
        domain = input_value

    level, is_correct, cipher = check_cipher_level(domain)

    if is_correct:
        print(f"{domain}: The TLS cipher level is {level} and it's correct.\nThe Cipher suite that this domain is using is: {cipher}")
    else:
        print(f"{domain}: {level} Cipher suite: {cipher}")
