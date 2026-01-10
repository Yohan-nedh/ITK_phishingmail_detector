# Parsing mail files
import re
import ipaddress
from bs4 import BeautifulSoup # Pour extraire les liens du contenu HTML, ne pas oublier d'installer html.parser


"""
Élements à extraire du mail:
- From
- To
- Subject
- Reply-To
- Received: L'ip d'origine; Toutes les ip, histoire de suivre la chaine de transfert et les champs received au complet
- ARC-Authentication-Results
- Authentication-Results
- Body
- Pièces jointes
- ...
"""


def extract_header_data(msg):
    from_ = msg.get("From", None) # from_ à cause du mot clé from
    to = msg.get("To", None)
    subject = msg.get("Subject", None)
    reply = msg.get("Reply-To", None)

    # Recupération des champs received et les ip dedans
    received_headers = msg.get_all("Received", failobj=[]) # Il n'y a pas qu'un seul received

    ip_pattern = re.compile(r"[\[\(]?([0-9A-Fa-z:.]+)[\]\)]?") # Ip potentiel(Toute chaine contenant . ou ::)
    valid_ips = []
    lastReceived_ips = []
    sender_ip = None

    count = 1
    for line in received_headers:
        for match in ip_pattern.findall(line):
            try:
                ip = ipaddress.ip_address(match)
                valid_ips.append(str(ip))
                if count == len(received_headers):
                    lastReceived_ips.append(str(ip))
            except ValueError:
                pass
        count += 1

    if lastReceived_ips:
        sender_ip = lastReceived_ips[0]


    # Recupération des auths headers et la vérifiaction des tests d'authentification(pass, fail, etc)
    auth_headers = []
    for header in ["Authentication-Results", "ARC-Authentication-Results"]:
        if header in msg:
            auth_headers.extend(msg.get_all(header))

    parsed_auth_headers = {}
    
    for auth_header in auth_headers:
        for part in auth_header.split(";"):
            part = part.strip()
            if part.startswith("spf="):
                parsed_auth_headers["SPF"] = part.split("=")[1].split()[0]
            elif part.startswith("dkim="):
                parsed_auth_headers["DKIM"] = part.split("=")[1].split()[0]
            elif part.startswith("dmarc="):
                parsed_auth_headers["DMARC"] = part.split("=")[1].split()[0]

    return {
        "from": from_,
        "to": to,
        "subject": subject,
        "reply_to": reply,
        "authentication_results": parsed_auth_headers,
        "received": {
            "raw": received_headers,
            "ips": valid_ips,
            "sender_ip": sender_ip
        }
    }


def extract_body_data(msg):
    text = ""
    html = ""
    files = []
    links = []
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get_content_disposition())

        if content_type == "text/plain":
            text += part.get_content() + '\n'
        elif content_type == "text/html":
            html += part.get_content() + '\n'

        if content_disposition == "attachment":
            filename = part.get_filename()
            files.append({
                'filename': filename,
                'content_type': content_type
            })
            continue
    if html:
        soup = BeautifulSoup(html, "html.parser") # Création de la soupe. La soupe, c'est ce qui va permettre d'extraire les trucs de l'html
        for a in soup.find_all("a", href=True):
            links.append((a.get_text(strip=True), a['href']))
    if text:
        url_regex = r'\b(?:https?://|www\.)[a-zA-Z0-9._\-~:/?#\[\]@!$&\'()*+,;=%]+(?<![)\],.;!?])'
        matches = re.findall(url_regex, text)
        links.extend(matches)

    return {"text": text.strip(), "html": html.strip(), "links": links, "attachments": files}
        
     
# Parsing with IMAP depuis une boîte mail: (À venir)



# Tafs restants à completer pour améliorer le parsing: (À venir)
"""
- Améliorer la détection de l'ip d'origine
- Le cas où il y a plusieurs tests ou champs (spf, dkim, dmarc)
- Le cas où il n'y aura pas d'adresse ip dans les champs received mais des hostname
- Revoir le regex ip, et faire le regex ipv4 et ipv6 à part, afin de mieux extraire les adresses
"""