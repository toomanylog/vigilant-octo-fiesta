import os, re, socket, masscan
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import requests

# Ranges d'IP à scanner
IP_RANGES = ["0.0.0.0/0"] # Attention, ceci va scanner tout l'internet

# Vérifie si une URL utilise Laravel
def check_laravel(url):
    headers = requests.get(url).headers
    return "laravel" in headers.get("Set-Cookie", "").lower()

# Vérifie si une URL est concernée par la faille gitleak
def check_gitleak(url):
    # Mettez ici votre logique pour vérifier la faille gitleak
    return False

# Scanne une IP
def scan_ip(ip):
    try:
        print(f"Scanning {ip}...")
        domains = socket.gethostbyaddr(ip)
        urls = [f"http://{domain}" for domain in domains[2]]

        online = any(requests.get(url).status_code == 200 for url in urls)
        laravel = any(check_laravel(url) for url in urls)
        gitleak = any(check_gitleak(url) for url in urls)

        return ip, online, domains[2], laravel, gitleak
    except socket.herror:
        return ip, False, [], False, False

# Fonction principale
def main():
    # Effectue un scan massif d'IP
    mas = masscan.PortScanner()
    mas.scan(','.join(IP_RANGES), ports="80")

    # Crée un ThreadPool pour scanner plusieurs IPs en parallèle
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_ip, ip) for ip in mas.all_ips]

        for future in concurrent.futures.as_completed(futures):
            ip, online, domains, laravel, gitleak = future.result()

            # Écriture des résultats dans les fichiers appropriés
            with open("online_ips.txt", "a") as f:
                if online:
                    f.write(ip + "\n")

            with open("laravel_domains.txt", "a") as f:
                if laravel:
                    for domain in domains:
                        f.write(domain + "\n")

            with open("gitleak_domains.txt", "a") as f:
                if gitleak:
                    for domain in domains:
                        f.write(domain + "\n")

            with open("all_domains.txt", "a") as f:
                for domain in domains:
                    f.write(domain + "\n")

if __name__ == "__main__":
    main()
