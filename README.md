# ITK_phishingmail_detector

`ITK_phishingmail_detector` is command line tool used to analyze email files(eml or txt) to detect phishing attempts.

**Why?** This tool was designed to automate the analysis of suspicious emails, provide a clear risk score and help users make informed decisions.

## Quick Start
```zsh
└─$ python3 phish_detector.py data/suspicious_mail.txt   


    ░█▀█░█░█░▀█▀░█▀▀░█░█░▀█▀░█▀█░█▀▀
    ░█▀▀░█▀█░░█░░▀▀█░█▀█░░█░░█░█░█░█
    ░▀░░░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀▀░▀░▀░▀▀▀
    ░█▀▀░█▄█░█▀█░▀█▀░█░░            
    ░█▀▀░█░█░█▀█░░█░░█░░            
    ░▀▀▀░▀░▀░▀░▀░▀▀▀░▀▀▀            
    ░█▀▄░█▀▀░▀█▀░█▀▀░█▀▀░▀█▀░█▀█░█▀▄
    ░█░█░█▀▀░░█░░█▀▀░█░░░░█░░█░█░█▀▄
    ░▀▀░░▀▀▀░░▀░░▀▀▀░▀▀▀░░▀░░▀▀▀░▀░▀


FILE ANALYSIS |***|
.
.
.
```

## Install
Make sure you have Python installed.

To use this tool, you need to clone this github repository (https://github.com/Yohan-nedh/ITK_phisingmail_detector.git) and install the requirements as follows:

```zsh
└─$ git clone https://github.com/Yohan-nedh/ITK_phisingmail_detector.git

└─$ cd ITK_phisingmail_detector.git

└─$ pip install -r requirements.txt
```
You can activate a python env before installing requirements file to avoid conflicts.

## How-to Guides
### How to view the help page
```zsh
└─$ python3 phish_detector.py --help
```

### How to analyze a file
```zsh
└─$ python3 phish_detector.py data/suspicious_mail.txt
```

### How to save the analysis results
```zsh
└─$ python3 phish_detector.py data/suspicious_mail.txt -o 
```

If you don't specify the output file, the results are automatically saved in data/phish_results.txt. You can also specify the output file:

```zsh
└─$ python3 phish_detector.py data/suspicious_mail.txt -o /path/to/output_file
```

### How to see the tool version
```zsh
└─$ python3 phish_detector.py --version
```