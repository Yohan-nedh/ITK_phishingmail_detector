"""
analyser.py
Analyse complète d'un email pour détecter le phishing
Compatible avec mail_parsing.py
"""

import re
import atexit
import vt
import tldextract
import Levenshtein # détection de typosquattage
import whois
import contextlib, io
import json, time
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from email.utils import parseaddr
from email.header import decode_header

vt_key_file = Path("data/vt_api_key.txt")
if vt_key_file.exists():
    try:
        vt_api_key = vt_key_file.read_text().strip()
    except Exception as e:
        print(f"Impossible de lire la clé VT : {e}")
        vt_api_key = ""
else:
    print("Fichier data/vt_api_key.txt introuvable → VirusTotal désactivé")
    vt_api_key = ""

#==== API VT (VirusTotal) ====
try:
    if vt_api_key:
        vt_client = vt.Client(vt_api_key)
        vt_available = True
    else:
        vt_client = None
        vt_available = False
except ImportError:
    print("Module 'vt' non installé → VirusTotal désactivé (pip install vt-py)")
    vt_client = None
    vt_available = False

# Optionnel: Au cas où l'user n'aura pas la connexion internet
try:
    import requests # pour résooudre les shortener, histoire de voir où ça mène vraiment
except Exception:
    requests = None

vt_cache_file = Path("data/vt_cache.json")
vt_cache_ttl = 86400 * 7  # 24 heures

# === CONFIGURATION LOCALE ===
WHITELIST_DOMAINS = {
    "paypal.com", "paypal.fr",
    "amazon.com", "amazon.fr", "stripe.com", "tryhackme.com",
    "banque-populaire.fr", "credit-agricole.fr", "labanquepostale.fr", "freecodecamp.org",
    "gmail.com", "outlook.com", "yahoo.com", "orange.fr", "free.fr", "portswigger.net", "coursera.org"

    # réseaux sociaux
    "discord.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "youtube.com", "facebook.com",

    # CDNs/trackers
    'googleusercontent.com','amazonaws.com','cloudfront.net'
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

FREEMAIL_DOMAINS = {
    "gmail.com",
    "yahoo.com", "yahoo.fr", "ymail.com",
    "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com", "msn.com",
    "aol.com",
    "icloud.com", "me.com",
    "protonmail.com", "proton.me",
    "gmx.com", "gmx.fr",
    "mail.com",
    "zoho.com",
    "yandex.com"
}

URL_SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".zip", ".rar"}
DANGEROUS_MIME = {"application/x-msdownload", "application/x-msdos-program", "application/x-executable", "application/javascript", "text/javascript"}

# === CACHE VIRUSTOTAL ===
def load_vt_cache():
    """Charge le cache VT"""
    if vt_cache_file.exists():
        try:
            return json.load(open(vt_cache_file))
        except:
            return {}
    return {}

def save_vt_cache(cache):
    """Sauvegarde le cache VT"""
    vt_cache_file.parent.mkdir(exist_ok=True)
    json.dump(cache, open(vt_cache_file, "w"), indent=2)

# === FONCTIONS UTILITAIRES ===
def normalize_email_addr(addr):
    """Nettoie le champ possible: 'Name <user@domain>' -> user@domain"""
    if not addr:
        return "", ""

    name, mail = parseaddr(addr)

    # Décodage RFC2047 éventuel (=?utf-8?...?=)
    if name:
        decoded = decode_header(name)
        name = "".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in decoded
        )

    return name, mail


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


def get_host(domain):
    """Extrait le host du domaine: amazon.com -> amazon, paypal.com -> paypal"""
    if not domain:
        return ""

    ext = tldextract.extract(domain)
    if ext.domain:
        return f"{ext.domain}"


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


CACHE_FILE = Path("data/whois_cache.json")
ERROR_TTL = 300

def load_whois_cache():
    """Charge le cache WHOIS"""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}


def save_whois_cache(cache):
    """Sauvegarde le cache WHOIS"""
    CACHE_FILE.parent.mkdir(exist_ok=True)
    json.dump(cache, open(CACHE_FILE, "w"), indent=2)


def get_domain_age(domain):
    """Retourne l'âge du domaine en jours, ou None si inconnu."""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()): # Pour ne pas afficher les erreurs dans la sortie
            w = whois.whois(domain)
    except Exception:
        return None

    creation = w.creation_date

    # Si c'est une liste, on prend la plus ancienne
    if isinstance(creation, list):
        creation = min(creation)

    # Peut être une string → on tente de parser
    if isinstance(creation, str):
        try:
            creation = datetime.fromisoformat(creation)
        except:
            return None

    # Vérifie que c'est bien un datetime
    if not isinstance(creation, datetime):
        return None

    # Neutraliser timezone-aware datetimes
    creation = creation.replace(tzinfo=None)

    age = (datetime.utcnow() - creation).days
    return age


def get_domain_age_cached(domain):
    now = int(time.time())
    cache = load_whois_cache()

    # entrée existante
    if domain in cache:
        entry = cache[domain]

        if "age" in entry:
            return entry["age"]

        if "error" in entry:
            # Erreur récente
            if now - entry["ts"] < ERROR_TTL:
                return None

    # Faire un WHOIS réel
    age = get_domain_age(domain)

    if age is not None:
        cache[domain] = {"age": age, "ts": now}
        save_whois_cache(cache)
        return age

    # Erreur: enregistrer une entrée temporaire
    cache[domain] = {"error": "timeout", "ts": now}
    save_whois_cache(cache)
    return None


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
        d = Levenshtein.distance(get_host(domain), get_host(cand))
        if best is None or d < best_d:
            best = cand
            best_d = d
    if best is not None and best_d <= max_distance and best != domain:
        return True, best, best_d
    return False, None, 0

# === VIRUSTOTAL INTEGRATION ===
vt_client = None
if vt_available and vt_api_key != "" and vt_api_key.strip():
    vt_client = vt.Client("data/vt_api_key.txt")

def check_url_vt(url):
    if not vt_available or not vt_client:
        return 0, []

    cache = load_vt_cache()
    now = int(time.time())

    if url in cache:
        if now - cache[url]["ts"] < vt_cache_ttl:
            stats = cache[url]["stats"]
            malicious = stats.get("malicious", 0) + stats.get("phishing", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0:
                return 60, [f"VirusTotal : {url} → {malicious} détections phishing/malveillant"]
            if suspicious > 0:
                return 25, [f"VirusTotal : {url} → {suspicious} détections suspectes"]
            return 0, [f"VirusTotal : {url} → propre"]

    try:
        analysis = vt_client.scan_url(url)
        # On attend pas forcément la fin du scan, on récupère le dernier connu
        obj = vt_client.get_object(f"/urls/{analysis.id.split('/')[-1]}")
        stats = obj.last_analysis_stats
        malicious = stats.get("malicious", 0) + stats.get("phishing", 0)
        suspicious = stats.get("suspicious", 0)

        cache[url] = {"stats": stats, "ts": now}
        save_vt_cache(cache)

        if malicious > 0:
            return 60, [f"VirusTotal : {url} → {malicious} détections graves !"]
        if suspicious > 0:
            return 25, [f"VirusTotal : {url} → {suspicious} alertes"]
        return 0, [f"VirusTotal : {url} → aucun problème détecté"]
    except Exception as e:
        return 0, [f"VirusTotal indisponible : {str(e)}"]


# === ANALYSES ===
def analyse_headers(headers):
    """Analyse les en-têtes (From, Reply-To, authentification)."""
    score = 0
    issues = []

    # --- Expéditeur ---
    from_raw = headers.get("from", "")
    reply_to_raw = headers.get("reply_to", "")

    from_username, from_addr = normalize_email_addr(from_raw)
    reply_to_username, reply_to = normalize_email_addr(reply_to_raw)

    from_reg = get_host_reg_domain(from_addr)
    reply_reg = get_host_reg_domain(reply_to)

    auth = headers.get("authentication_results", {})

    if from_addr and reply_to and from_reg != reply_reg:
        dmarc_check = auth.get("DMARC", "").lower()
        if dmarc_check:
            if dmarc_check in ["fail", "permerror"]:
                score += 30
                issues.append(f"Incohérence entre les champs 'De' et 'Répondre à': {from_reg} != {reply_reg}, avec échec du dmarc")

        if from_reg not in FREEMAIL_DOMAINS and reply_reg in FREEMAIL_DOMAINS:
            score += 20
            issues.append(f"Incohérence entre les champs 'De' et 'Répondre à': {from_reg} != {reply_reg}, reply-to pointe vers une adresse privée alors que l'emetteur est une entreprise")

        if from_reg not in FREEMAIL_DOMAINS and reply_reg not in FREEMAIL_DOMAINS:
            score += 10


        if from_username and reply_to_username and from_username != reply_to_username:
            score += 20
            issues.append(f"Incohérence entre les usernames des champs 'De' et 'Répondre à': {from_username} != {reply_to_username}")

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
                    age = get_domain_age_cached(from_reg)

                    if age is None:
                        score += 10    # pas d’info WHOIS: léger risque
                        issues.append(f"Pas d'informations whois sur le domaine : {from_reg}")
                    elif age < 30:
                        score += 30    # domaine ultra récent: gros risque
                        issues.append(f"Domaine très récent : {from_reg}")
                    elif age < 180:
                        score += 20    # domaine récent
                        issues.append(f"Domaine récent : {from_reg}")
                    elif age < 365:
                        score += 10    # domaine jeune
                        issues.append(f"Domaine jeune : {from_reg}")
                    else:
                        score += 3
                        issues.append(f"Domaine ancien, risque faible : {from_reg}")


    # --- Authentification (SPF, DKIM, DMARC) ---
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
    if received_len >= 8:
        score += 5
        issues.append(f"Trop de serveurs relais: {received_len}")

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


def analyse_liens(body, sender_domain):
    """Analyse les liens (usurpation, raccourcisseur, domaine)."""
    score, issues = 0, []
    links = body.get("links", [])
    seen = set()

    for link in links:
        if isinstance(link, str):
            url = link
            display = link
        else:
            display, url = link

        url_domain = get_url_reg_domain(url)
        if not url_domain or url_domain in seen:
            continue
        seen.add(url_domain)

        # VT check
        vt_score, vt_issues = check_url_vt(url)
        score += vt_score
        issues.extend(vt_issues)

        # Lien usurpé
        if display != url and get_url_reg_domain(display) != url_domain:
            score += 30
            issues.append(f"Lien usurpé : affiche « {display} » → {url_domain}")

        # Shortener
        if is_shortener(url):
            score += 20
            issues.append(f"Raccourcisseur détecté : {url_domain}")
            if resolved := resolve_shortener(url):
                issues.append(f"→ redirige vers {get_url_reg_domain(resolved)}")

        # Domaine externe + jeune
        if sender_domain and url_domain != sender_domain and url_domain not in WHITELIST_DOMAINS:
            age = get_domain_age_cached(url_domain)
            if age is not None and age < 90:
                score += 25
                issues.append(f"Lien externe récent : {url_domain} ({age} jours)")

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

    _, sender_domain_reg = normalize_email_addr(headers.get("from", ""))
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

    true_score = total_score
    total_score = min(total_score, 100)

    if total_score >= 70:
        niveau = "Élevé"
    elif total_score >= 40:
        niveau = "Modéré"
    else:
        niveau = "Faible"

    return {
        'true_score': true_score,
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

# Fermeture propre du client VT à la fin du programme

if vt_client:
    atexit.register(vt_client.close)


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
- Revoir is_lookalike pour détecter les attaques d'homoglyphes
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
