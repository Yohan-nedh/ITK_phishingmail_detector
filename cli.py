"""
cli.py
Interface en ligne de commande pour l'analyse des emails"""
import argparse
from pathlib import Path
from analyzer import analyser_email, save_results


def main():
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
    
    GREEN = "\033[92m"
    RESET = "\033[0m"
    print(f"{GREEN}ANALYSE DU FICHIER |***|{RESET}\n")


    VERSION = "1.0.0"

    parser = argparse.ArgumentParser(prog="phishingmail_detector", description="Analyze email to detect phishing attempts")
    parser.add_argument("filepath", help="path of file to analyze")
    parser.add_argument("-o", "--output", help="save the analysis in file", nargs="?", const="data/phish_results.txt", default=None)
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    args = parser.parse_args()

    fp = Path(args.filepath)
    if not fp.exists():
        parser.error(f"{fp} don't exist")
    else:
        results = analyser_email(fp)
        if  args.output:
            save_results(args.output, results, fp)