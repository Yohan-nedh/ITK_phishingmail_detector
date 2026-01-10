"""
analyzer.py
Analyse complète d'un email pour détecter le phishing
Compatible avec mail_parsing.py
"""

import re
import atexit
import vt
import tldextract
import Levenshtein  # détection de typosquattage
import whois
import contextlib
import io
import json
import time
import requests
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
from email.utils import parseaddr
from email.header import decode_header
from email.parser import BytesParser
from email import policy

from mail_parsing import extract_header_data, extract_body_data


# === CONFIGURATION FICHIERS ===
vt_key_file = Path("data/vt_api_key.txt")
vt_cache_file = Path("data/vt_cache.json")
CACHE_FILE = Path("data/whois_cache.json")


# === CHARGEMENT CLÉ VIRUSTOTAL ===
vt_api_key = ""
if vt_key_file.exists():
    try:
        vt_api_key = vt_key_file.read_text().strip()
    except Exception as e:
        print(f"Impossible de lire la clé VT : {e}")
else:
    print("Fichier data/vt_api_key.txt introuvable → VirusTotal désactivé")

# === INITIALISATION VIRUSTOTAL ===
vt_client = None
vt_available = False

if vt_api_key:
    try:
        vt_client = vt.Client(vt_api_key)
        vt_available = True
    except ImportError:
        print("Module 'vt' non installé → VirusTotal désactivé (pip install vt-py)")
    except Exception as e:
        print(f"Erreur d'initialisation VirusTotal : {e}")
else:
    print("Clé VirusTotal absente → VirusTotal désactivé")

vt_cache_ttl = 86400 * 7  # 7 jours


# === CONFIGURATION LOCALE ===
WHITELIST_DOMAINS = {
    "paypal.com", "paypal.fr",
    "amazon.com", "amazon.fr", "stripe.com", "tryhackme.com",
    "banque-populaire.fr", "credit-agricole.fr", "labanquepostale.fr", "freecodecamp.org",
    "gmail.com", "outlook.com", "yahoo.com", "orange.fr", "free.fr", "portswigger.net", "coursera.org",
    # réseaux sociaux
    "discord.com", "twitter.com", "x.com",
    "instagram.com", "linkedin.com", "youtube.com", "facebook.com",
    # CDNs/trackers
    "googleusercontent.com", "amazonaws.com", "cloudfront.net"
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
    "gmail.com", "yahoo.com", "yahoo.fr", "ymail.com",
    "hotmail.com", "hotmail.fr", "outlook.com", "outlook.fr", "live.com", "msn.com",
    "aol.com", "icloud.com", "me.com",
    "protonmail.com", "proton.me",
    "gmx.com", "gmx.fr",
    "mail.com",
    "zoho.com",
    "yandex.com"
}

URL_SHORTENERS = {"bit.ly", "t.co", "goo.gl", "tinyurl.com", "ow.ly"}
DANGEROUS_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".ps1", ".zip", ".rar"}
DANGEROUS_MIME = {
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-executable",
    "application/javascript",
    "text/javascript"
}


# === CACHE VIRUSTOTAL ===
def load_vt_cache():
    if vt_cache_file.exists():
        try:
            return json.load(vt_cache_file.open("r"))
        except:
            return {}
    return {}


def save_vt_cache(cache):
    vt_cache_file.parent.mkdir(exist_ok=True)
    json.dump(cache, vt_cache_file.open("w"), indent=2)


# === CACHE WHOIS ===
def load_whois_cache():
    if CACHE_FILE.exists():
        try:
            return json.load(CACHE_FILE.open("r"))
        except:
            return {}
    return {}


def save_whois_cache(cache):
    CACHE_FILE.parent.mkdir(exist_ok=True)
    json.dump(cache, CACHE_FILE.open("w"), indent=2)


# === FONCTIONS UTILITAIRES ===
def normalize_email_addr(addr):
    if not addr:
        return "", ""
    name, mail = parseaddr(addr)
    if name:
        decoded = decode_header(name)
        name = "".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in decoded
        )
    return name, mail


def get_host_reg_domain(hostname):
    if not hostname:
        return ""
    if "@" in hostname and hostname.count("@") == 1 and not hostname.startswith("http"):
        hostname = hostname.split("@")[-1]
    hostname = hostname.strip().lower()
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    if ":" in hostname and not "::" in hostname:
        hostname = hostname.split(":")[0]
    ext = tldextract.extract(hostname)
    if ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain


def get_host(domain):
    if not domain:
        return ""
    ext = tldextract.extract(domain)
    return ext.domain


def get_url_reg_domain(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
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
        if ":" in host and not "::" in host:
            host = host.split(":")[0]
        return host.lower().strip()
    except Exception:
        return ""


def get_domain_age(domain):
    """Retourne l'âge du domaine en jours, ou None si inconnu."""
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            w = whois.whois(domain)
    except Exception:
        return None

    creation = w.creation_date

    if isinstance(creation, list):
        creation = min(creation)

    if isinstance(creation, str):
        try:
            creation = datetime.fromisoformat(creation)
        except:
            return None

    if not isinstance(creation, datetime):
        return None

    # Neutraliser timezone
    creation = creation.replace(tzinfo=None)

    age = (datetime.utcnow() - creation).days
    return age


def get_domain_age_cached(domain):
    now = int(time.time())
    cache = load_whois_cache()

    if domain in cache:
        entry = cache[domain]
        if "age" in entry:
            return entry["age"]
        if "error" in entry and now - entry["ts"] < 300:
            return None

    age = get_domain_age(domain)

    if age is not None:
        cache[domain] = {"age": age, "ts": now}
    else:
        cache[domain] = {"error": "timeout", "ts": now}

    save_whois_cache(cache)
    return age


def is_shortener(hostname):
    return get_host_reg_domain(hostname) in URL_SHORTENERS


def resolve_shortener(url, timeout=3.0):
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
    if not domain:
        return False, None, 0
    domain = domain.lower()
    if candidates is None:
        candidates = list(WHITELIST_DOMAINS)
    best = None
    best_d = float('inf')
    for cand in candidates:
        d = Levenshtein.distance(get_host(domain), get_host(cand))
        if d < best_d:
            best = cand
            best_d = d
    if best is not None and best_d <= max_distance and best != domain:
        return True, best, best_d
    return False, None, 0


# === VIRUSTOTAL CHECK ===
def check_url_vt(url):
    if not vt_available or not vt_client:
        return 0, []

    cache = load_vt_cache()
    now = int(time.time())

    if url in cache and now - cache[url]["ts"] < vt_cache_ttl:
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


# === FONCTIONS D'ANALYSE ===
def analyse_headers(headers):
    score = 0
    issues = []

    from_raw = headers.get("from", "")
    reply_to_raw = headers.get("reply_to", "")

    from_username, from_addr = normalize_email_addr(from_raw)
    reply_to_username, reply_to = normalize_email_addr(reply_to_raw)

    from_reg = get_host_reg_domain(from_addr)
    reply_reg = get_host_reg_domain(reply_to)

    auth = headers.get("authentication_results", {})

    if from_addr and reply_to and from_reg != reply_reg:
        dmarc_check = auth.get("DMARC", "").lower()
        if dmarc_check in ["fail", "permerror"]:
            score += 30
            issues.append(f"Incohérence 'De'/'Répondre à' + échec DMARC : {from_reg} != {reply_reg}")
        if from_reg not in FREEMAIL_DOMAINS and reply_reg in FREEMAIL_DOMAINS:
            score += 20
            issues.append(f"Reply-To pointe vers une adresse perso : {reply_reg}")
        if from_reg not in FREEMAIL_DOMAINS and reply_reg not in FREEMAIL_DOMAINS:
            score += 10

        if from_username and reply_to_username and from_username != reply_to_username:
            score += 20
            issues.append(f"Username différent : {from_username} ≠ {reply_to_username}")

    if from_reg:
        if from_reg in BLACKLIST_DOMAINS:
            score += 50
            issues.append(f"Domaine blacklisté : {from_reg}")
        else:
            lookalike, true_domain, dist = is_lookalike(from_reg)
            if lookalike:
                score += 20
                issues.append(f"Typosquattage probable : {from_reg} ≈ {true_domain} (dist={dist})")

            if from_reg not in WHITELIST_DOMAINS:
                if any(legit in from_reg for legit in ["paypal", "amazon", "banque", "gmail"]):
                    score += 40
                    issues.append(f"Domaine potentiellement falsifié : {from_reg}")
                else:
                    age = get_domain_age_cached(from_reg)
                    if age is None:
                        score += 10
                        issues.append(f"Pas d'info WHOIS : {from_reg}")
                    elif age < 30:
                        score += 30
                        issues.append(f"Domaine très récent : {from_reg} ({age} jours)")
                    elif age < 180:
                        score += 20
                        issues.append(f"Domaine récent : {from_reg} ({age} jours)")
                    elif age < 365:
                        score += 10
                        issues.append(f"Domaine jeune : {from_reg} ({age} jours)")
                    else:
                        score += 3
                        issues.append(f"Domaine ancien : {from_reg}")

    for protocol in ["SPF", "DKIM", "DMARC"]:
        result = auth.get(protocol, "").lower()
        if result in ["fail", "permerror"]:
            score += 30
            issues.append(f"{protocol} a échoué")
        elif result == "none":
            score += 15
            issues.append(f"{protocol} absent")

    subject = headers.get("subject", "").lower()
    if any(word in subject for word in ["urgent", "immédiat", "bloqué", "suspendu"]):
        score += 20
        issues.append("Sujet alarmiste")
    if "compte" in subject and ("bloqué" in subject or "suspendu" in subject):
        score += 25
        issues.append("Phrase typique de phishing dans le sujet")

    received_headers = headers.get("received", {}).get("raw", [])
    if len(received_headers) >= 8:
        score += 5
        issues.append(f"Trop de serveurs relais : {len(received_headers)}")

    return score, issues


def analyse_corps(body):
    score = 0
    issues = []
    text = body.get("text", "").lower()

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            score += 10
            issues.append(f"Mot suspect : « {keyword} »")

    return score, issues


def analyse_liens(body, sender_domain):
    score = 0
    issues = []
    links = body.get("links", [])
    seen = set()

    for link in links:
        if isinstance(link, str):
            url = display = link
        else:
            display, url = link

        url_domain = get_url_reg_domain(url)
        if not url_domain or url_domain in seen:
            continue
        seen.add(url_domain)

        vt_score, vt_issues = check_url_vt(url)
        score += vt_score
        issues.extend(vt_issues)

        if display != url and get_url_reg_domain(display) != url_domain:
            score += 30
            issues.append(f"Lien usurpé : affiche « {display} » → {url_domain}")

        if is_shortener(url):
            score += 20
            issues.append(f"Raccourcisseur détecté : {url_domain}")
            if resolved := resolve_shortener(url):
                issues.append(f"→ redirige vers {get_url_reg_domain(resolved)}")

        if sender_domain and url_domain != sender_domain and url_domain not in WHITELIST_DOMAINS:
            age = get_domain_age_cached(url_domain)
            if age is not None and age < 90:
                score += 25
                issues.append(f"Lien externe récent : {url_domain} ({age} jours)")

    return score, issues


def analyse_pieces_jointes(body):
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
            issues.append(f"Double extension suspecte : {fname}")

        if mime in DANGEROUS_MIME:
            score += 40
            issues.append(f"MIME dangereux : {mime} pour {fname}")

    return score, issues


# === FONCTION PRINCIPALE ===
def detecter_phishing(headers, body):
    total_score = 0
    all_issues = []

    _, sender_domain_reg = normalize_email_addr(headers.get("from", ""))
    sender_domain_reg = get_host_reg_domain(sender_domain_reg)

    analyses = [
        analyse_headers(headers),
        analyse_corps(body),
        analyse_liens(body, sender_domain_reg),
        analyse_pieces_jointes(body)
    ]

    for s, i in analyses:
        total_score += s
        all_issues.extend(i)

    # Dédoublonnage des issues
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


# === INTERFACE CONSOLE ===
RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"


def analyser_email(chemin_fichier):
    try:
        with open(chemin_fichier, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        headers = extract_header_data(msg)
        body = extract_body_data(msg)

        result = detecter_phishing(headers, body)

        print(f"\nSCORE : {result['score']}/100 ({result['niveau_risque']})\n")

        if result['problemes']:
            print(f"{RED}PROBLÈMES DÉTECTÉS :{RESET}")
            for p in result['problemes']:
                print(f" • {p}")
        else:
            print(f"{GREEN}Aucun problème détecté.{RESET}")

        if result['recommandations']:
            print(f"\n{RED}RECOMMANDATIONS :{RESET}")
            for r in result['recommandations']:
                print(f" • {r}")

        return result

    except Exception as e:
        print(f"{RED}Erreur lors de l'analyse : {e}{RESET}")
        return {}


def save_results(file, results, filepath):
    with open(file, "w", encoding="utf-8") as of:
        of.write(f"ITK_PHISHINGMAIL_DETECTOR RESULTS\t({datetime.now()})\n\n")
        of.write(f"FILE: {filepath}\n\n")
        of.write(f"SCORE : {results['score']}/100 ({results['niveau_risque']})\n\n")
        if results['problemes']:
            of.write("PROBLÈMES DÉTECTÉS :\n")
            for p in results['problemes']:
                of.write(f" • {p}\n")
        else:
            of.write("Aucun problème détecté.\n")

        if results['recommandations']:
            of.write("\nRECOMMANDATIONS :\n")
            for r in results['recommandations']:
                of.write(f" • {r}\n")

    print(f"\n{GREEN}Résultats sauvegardés dans {file}{RESET}")


# Fermeture propre du client VT
if vt_client:
    atexit.register(vt_client.close)


if __name__ == "__main__":
    # Petit test rapide si lancé directement
    print("Module analyzer.py chargé. Utilisez analyser_email(chemin) pour analyser un email.")