"""
analyser.py
Analyse complète d'un email pour détecter le phishing
Compatible avec mail_parsing.py
"""

import re
import tldextract
import Levenshtein # détection de typosquattage
from urllib.parse import urlparse

# Optionnel: Au cas où l'user n'aura pas la connexion internet
try:
    import requests # pour résooudre les shortener, histoire de voir où ça mène vraiment 
except Exception:
    requests = None


# === CONFIGURATION LOCALE ===
WHITELIST_DOMAINS = {
    "paypal.com", "paypal.fr",
    "amazon.com", "amazon.fr",
    "banque-populaire.fr", "credit-agricole.fr", "labanquepostale.fr",
    "gmail.com", "outlook.com", "yahoo.com", "orange.fr", "free.fr", "portswigger.net"
}

SUSPICIOUS_KEYWORDS = [
    "urgent", "immédiatement", "bloqué", "suspendu", "désactivé",
    "cliquez ici", "vérifiez votre compte", "mot de passe", "confidentiel",
    "mise à jour", "sécurité", "paiement", "facture", "problème",
    "action requise", "identifiez-vous", "cher client", "connexion", "accès"
]

BLACKLIST_DOMAINS = {
    "paypa1.com", "amaz0n-security.com", "gma1l.com",
    "paypal-support.net", "banque-securite.com", "amazon-verification.org"
}

URL_SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".zip", ".rar"}
DANGEROUS_MIME = {"application/x-msdownload", "application/x-msdos-program", "application/x-executable", "application/javascript", "text/javascript"}


# === FONCTIONS UTILITAIRES ===
def normalize_email_addr(addr):
    """Nettoie le champ possible: 'Name <user@domain>' -> user@domain"""
    if not addr:
        return ""
    if "<" in addr and ">" in addr:
        last = addr[addr.find("<") + 1: addr.find(">")]
        return last.strip().lower()
    return addr.strip().lower()


def get_host_reg_domain(hostname):
    """Extrait le domaine enrégistré d'un hostname."""
    if not hostname:
        return ""
    if "@" in hostname and hostname.count("@") == 1 and not hostname.startswith("http"):
        hostname = hostname.split("@")[-1]

    hostname = hostname.strip().lower()
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    
    if ":" in hostname and not ":" in hostname.replace("::", ""):
        hostname = hostname.split(":")[0]

    ext = tldextract.extract(hostname)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain


def get_url_reg_domain(url):
    """Extrait le nom de domaine d'une URL."""
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path # parfois url est sans scheme(http, https,...)
        # si host contient credentials (user:pass@host)
        if "@" in host:
            host = host.split("@")[-1]
        return get_host_reg_domain(host)
    except Exception:
        return ""


def extract_host_from_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        if "@" in host:
            host = host.split("@")[-1]
        # strip port
        if ":" in host and not ":" in host.replace("::", ""):
            host = host.split(":")[0]
        return host.lower().strip()
    except Exception:
        return ""


def is_shortener(hostname):
    """Pour voir si le hostname est un shortener"""
    rd = get_host_reg_domain(hostname)
    return rd in URL_SHORTENERS


def resolve_shortener(url, timeout=3.0):
    """Suivre les redirections d'un shortener pour récupérer la destination finale"""
    if not requests:
        return None
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception:
        try:
            r = requests.get(url, allow_redirects=True, timeout=timeout)
            return r.url
        except Exception:
            return None


def is_lookalike(domain, candidates=None, max_distance=2):
    """Détecte le typosquattage"""
    if not domain:
        return False, None, 0
    domain = domain.lower()
    if candidates is None:
        candidates = list(WHITELIST_DOMAINS)
    best = None
    best_d = None
    for cand in candidates:
        d = Levenshtein.distance(domain, cand)
    if best is None or d < best_d:
        best = cand
        best_d = d
    if best is not None and best_d <= max_distance and best != domain:
        return True, best, best_d
    return False, None, 0


# === ANALYSES ===
def analyse_headers(headers):
    """Analyse les en-têtes (From, Reply-To, authentification)."""
    score = 0
    issues = []

    # --- Expéditeur ---
    from_raw = headers.get("from", "")
    reply_to_raw = headers.get("reply_to", "")
    from_addr = normalize_email_addr(from_raw)
    reply_to = normalize_email_addr(reply_to_raw)
    from_reg = get_host_reg_domain(from_addr)
    reply_reg = get_host_reg_domain(reply_to)
    
    if from_addr and reply_to and from_reg != reply_reg:
        score += 30
        issues.append(f"Incohérence entre les champs 'De' et 'Répondre à': {from_reg} != {reply_reg}")

    if from_reg:
        if from_reg in BLACKLIST_DOMAINS:
            score += 50
            issues.append(f"Domaine connu pour phishing : {from_reg}")
        else:
            lookalike, true_domain, dist = is_lookalike(from_reg)
            if lookalike:
                score += 20
                issues.append(f"{from_reg} ressemble à {true_domain} (d={dist})")
            
            if from_reg not in WHITELIST_DOMAINS:
                if any(legit in from_reg for legit in ["paypal", "amazon", "banque", "gmail"]): # À revoir, ça va créer trop de faux positifs, le cas de 
                    score += 40
                    issues.append(f"Domaine falsifié : {from_reg}")
                else:
                    score += 20
                    issues.append(f"Domaine non reconnu : {from_reg}")


    # --- Authentification (SPF, DKIM, DMARC) ---
    auth = headers.get("authentication_results", {})
    for protocol in ["SPF", "DKIM", "DMARC"]:
        result = auth.get(protocol, "").lower()
        if result and result in ["fail", "permerror"]:
            score += 30
            issues.append(f"{protocol} a échoué")
        elif result and result == "none":
            score += 15
            issues.append(f"{protocol} absent")

    # --- Sujet ---
    subject = headers.get("subject", "").lower()
    if any(word in subject for word in ["urgent", "immédiat", "bloqué", "suspendu"]):
        score += 20
        issues.append("Sujet alarmiste")
    if "compte" in subject and ("bloqué" in subject or "suspendu" in subject):
        score += 25
        issues.append("Phrase typique de phishing dans le sujet")

    # --- Champs Received pour le nombre de serveurs relais ---
    received_headers = headers.get("received", {}).get("raw", [])
    received_len = len(received_headers)
    if received_len >= 6:
        score += 15
        issues.append("Trop de serveurs relais: ", received_len)
        
        sender_ip = headers.get("received", {}).get("sender_ip", "")
        issues.append(f"Adresse IP de l'emetteur: {sender_ip}")

    return score, issues


def analyse_corps(body):
    """Analyse le texte du corps."""
    score = 0
    issues = []
    text = body.get("text", "").lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            score += 10
            issues.append(f"Mot suspect : « {keyword} »")

    return score, issues


def analyse_liens(body, sender_domain_reg):
    """Analyse les liens (usurpation, raccourcisseur, domaine)."""
    score = 0
    issues = []
    links = body.get("links", [])

    url_regex = r'\b(?:https?://|www\.)[a-zA-Z0-9._\-~:/?#\[\]@!$&\'()*+,;=%]+(?<![)\],.;!?])'

    analysed_links = set() # Pour éviter les mêmes liens ne soient analysés plusieurs fois surtout dans les cas, où on appelera requests
    for link in links:
        if link in analysed_links:
            continue
        # Si c'est une URL brute (str), pas un tuple
        if isinstance(link, str):
            url = link
            display_text = url
        else:
            display_text, url = link

        host = extract_host_from_url(url)
        if not host:
            continue
        url_reg = get_url_reg_domain(url)
        
        # Domaine dans la liste noire
        if url_reg in BLACKLIST_DOMAINS:
            score += 50
            issues.append(f"Domaine malveillant : {url_domain}")

        # Détection de typosquattage
        look, match, dist = is_lookalike(url_reg)
        if look:
            score += 40
            issues.append(f"Possible typosquat: {url_reg} ressemble à {match} (d={dist})")
        
        # Lien usurpé (texte ≠ domaine)
        matches = re.findall(url_regex, display_text)
        if matches:
            for l in matches:
                domain_in_text = get_url_reg_domain(l)
                if domain_in_text and domain_in_text != url_reg:
                    score += 25
                    issues.append(f"Lien usurpé : « {l} » mais pointe vers {url_reg}")
        

        # Domaine différent de l'expéditeur
        if sender_domain_reg and sender_domain_reg not in url_reg:
            if url_reg not in {'googleusercontent.com','amazonaws.com','cloudfront.net','facebook.com', 'portswigger.net'}: # Pour ne pas trop agressif envers les CDNs/trackers courants
                score += 20
                issues.append(f"Lien externe : {url_reg} (expéditeur: {sender_domain_reg})")
               
        # Raccourcisseur
        if is_shortener(host):
            score += 20
            issues.append(f"Raccourcisseur détecté : {url_reg}")
             # Optionnel: Résoud shortener si connexion internet
            if requests:
                resolved = resolve_shortener(url)
                if resolved and resolved != href:
                    dest_reg = get_registered_domain_from_url(resolved)
                    issues.append(f"Shortener résolu vers {dest_reg}")
                    # reévaluer resolved dest
                    if dest_reg in BLACKLIST_DOMAINS:
                        score += 50
                        issues.append(f"Destination shortener en blacklist: {dest_reg}")
        
        analysed_links.add(link)
    return score, issues


def analyse_pieces_jointes(body):
    """Analyse les pièces jointes."""
    score = 0
    issues = []
    files = body.get("attachments", [])

    for f in files:
        fname = f.get('filename', '')
        mime = f.get('content_type', '').lower()

        ext = ('.' + fname.rsplit('.', 1)[-1].lower()) if '.' in fname else ''
        double_exts = re.findall(r"\.([a-z0-9]{1,6})", fname.lower())

        if ext in DANGEROUS_EXT:
            score += 50
            issues.append(f"Pièce jointe dangereuse : {fname}")
        if any('.' + e in DANGEROUS_EXT for e in double_exts[-2:]):
            score += 60
            issues.append(f"Double extension suspecte: {fname}")

        if mime in DANGEROUS_MIME:
            score += 40
            issues.append(f"MIME dangereux: {mime} pour {fname}")

    return score, issues


# === FONCTION PRINCIPALE ===
def detecter_phishing(headers, body):
    """Analyse complète de l'email."""
    total_score = 0
    all_issues = []

    sender_domain_reg = normalize_email_addr(headers.get("from", ""))
    sender_domain_reg = get_host_reg_domain(sender_domain_reg)

    # Toutes les analyses
    analyses = [
        analyse_headers(headers),
        analyse_corps(body),
        analyse_liens(body, sender_domain_reg),
        analyse_pieces_jointes(body)
    ]

    for s, i in analyses:
        total_score += s
        all_issues.extend(i)

    unique_issues = []
    seen = set()

    for issue in all_issues:
        if issue not in seen:
            seen.add(issue)
            unique_issues.append(issue)

    total_score = min(total_score, 100)

    if total_score >= 70:
        niveau = "Élevé"
    elif total_score >= 40:
        niveau = "Modéré"
    else:
        niveau = "Faible"

    return {
        "score": total_score,
        "niveau_risque": niveau,
        "problemes": unique_issues,
        "recommandations": [
            "Ne cliquez sur aucun lien",
            "Ne téléchargez pas les pièces jointes",
            "Signalez cet email comme spam",
            "Contactez l’expéditeur via un canal officiel"
        ] if total_score >= 50 else []
    }




"""
MODIFS:
- Ajout des fonctions: normalize_email_addr(), 
                       get_host_reg_domain(),
                       extract_host_from_url(),
                       is_shortener(),
                       resolve_shortener(),
                       is_lookalike(),


- Complément et modif de la fonction take_url() en extract_host_>
- Ajout de l'analyse des champs received
- Affichage des problèmes sans duplication à la fin
- Et quelques autres petites modifs...
"""


"""
AUTRES REMARQUES:
- La white list, black list, suspicious word ne sont pas assez exhaustives. Ça peut biaiser les résultats. DOnc, on va revoir ça.
- Suspicious keyword est en français, dans le cas où le mail est dans une autre langue.....
"""






"""
from mail_parsing import extract_header_data, extract_body_data
from email.parser import BytesParser
from email import policy
with open('data/suspicious_mail.txt', "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

headers = extract_header_data(msg)

sender_domain_reg = get_host_reg_domain(normalize_email_addr(headers.get("from", "")))
print(headers.get("from", ""))
print()
print(sender_domain_reg)
"""