# main.py
import os
from mail_parsing import extract_header_data, extract_body_data
from analyser import detecter_phishing
from email.parser import BytesParser
from email import policy

# === FICHIER DE TEST PHISHING (à créer si absent) ===
PHISHING_EMAIL_CONTENT = """From: "PayPal" <support@paypa1.com>
To: client@exemple.com
Subject: URGENT : Votre compte PayPal sera bloqué
Reply-To: reply@hacker.ru
Date: Mon, 1 Jan 2024 12:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset=utf-8

Bonjour,

Votre compte PayPal présente une activité suspecte.
Cliquez ici pour vérifier : http://bit.ly/3fake-paypal

--boundary123
Content-Type: text/html; charset=utf-8

<html>
<body>
<p><strong>URGENT</strong> : Votre compte sera <u>bloqué dans 24h</u>.</p>
<p><a href="http://paypa1-login.com">Connexion sécurisée</a></p>
<p>Pièce jointe : <a href="update.exe">Mise à jour PayPal</a></p>
</body>
</html>

--boundary123--
"""

def creer_fichier_test(chemin):
    """Crée un email phishing de test si absent."""
    dossier = os.path.dirname(chemin)
    if dossier and not os.path.exists(dossier):
        os.makedirs(dossier)
        print(f"Dossier créé : {dossier}")

    with open(chemin, "w", encoding="utf-8") as f:
        f.write(PHISHING_EMAIL_CONTENT)
    print(f"Fichier de test créé : {chemin}")

def analyser_email(chemin_fichier):
    """Analyse ou crée l'email et l'analyse."""
    if not os.path.exists(chemin_fichier):
        print("Fichier non trouvé → création d'un email phishing de test...")
        creer_fichier_test(chemin_fichier)

    try:
        with open(chemin_fichier, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)

        headers = extract_header_data(msg)
        body = extract_body_data(msg)

        result = detecter_phishing(headers, body)

        print(f"\nSCORE : {result['score']}/100 ({result['niveau_risque']})\n")
        if result['problemes']:
            print("PROBLÈMES DÉTECTÉS :")
            for p in result['problemes']:
                print(f" • {p}")
        else:
            print("Aucun problème détecté.")

        if result['recommandations']:
            print("\nRECOMMANDATIONS :")
            for r in result['recommandations']:
                print(f" • {r}")

    except Exception as e:
        print(f"Erreur lors de l'analyse : {e}")


# === LANCEMENT ===
if __name__ == "__main__":
    chemin = "data/suspicious_mail.txt"
    ascii_art = r'''

		░█▀█░█░█░▀█▀░█▀▀░█░█░▀█▀░█▀█░█▀▀
		░█▀▀░█▀█░░█░░▀▀█░█▀█░░█░░█░█░█░█
		░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀▀▀
		░█▀▀░█▄█░█▀█░▀█▀░█░░            
		░█▀▀░█░█░█▀█░░█░░█░░            
		░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀            
		░█▀▄░█▀▀░▀█▀░█▀▀░█▀▀░▀█▀░█▀█░█▀▄
		░█░█░█▀▀░░█░░█▀▀░█░░░░█░░█░█░█▀▄
		░▀▀░░▀▀▀░░▀░░▀▀▀░▀▀▀░░▀░░▀▀▀░▀░▀

	 '''
    print(ascii_art)
    
    G = "\033[92m"
    RESET = "\033[0m"
    print(f"{G}ANALYSE DU FICHIER |***|{RESET}")
    analyser_email(chemin)
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
