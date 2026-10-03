\# IOC Checker



A web-based tool for SOC analysts that checks URLs, IP addresses and file hashes for suspicious indicators and gives a risk score with a clear verdict.



\*\*Live demo:\*\* coming soon



\## Features



\- Automatically detects the input type: URL, IP address or file hash (MD5, SHA-1, SHA-256)

\- Risk score from 0 to 100 with a verdict: LOW RISK, SUSPICIOUS or HIGH RISK

\- Shows every finding that contributed to the score

\- Works without any external API for URL analysis



\## URL Checks



\- IP address used instead of a domain name

\- `@` symbol hiding the real destination

\- No HTTPS

\- Very long URLs

\- Too many subdomains or hyphens

\- Suspicious top-level domains (.xyz, .top, .tk and others)

\- Punycode (look-alike characters)

\- URL shorteners

\- Non-standard ports

\- Phishing keywords (login, verify, secure, account and others)

\- Brand impersonation (for example `paypal.com.fake-site.xyz`)



\## Verdict Levels



| Score | Verdict |

|-------|---------|

| 0 to 29 | LOW RISK |

| 30 to 59 | SUSPICIOUS |

| 60 to 100 | HIGH RISK |



\## Tech Stack



\- Python 3

\- Flask

\- Jinja2 templates

\- Gunicorn (production server)

\- Deployed on Render



\## Run Locally



```

git clone https://github.com/Bhawna45/ioc-checker.git

cd ioc-checker

python -m venv venv

venv\\Scripts\\activate

pip install -r requirements.txt

python app.py

```



Then open `http://127.0.0.1:5000` in your browser.



\## Project Structure



```

ioc-checker/

├── app.py            # Flask app and routes

├── checker.py        # IOC type detection and scoring logic

├── requirements.txt

└── templates/

&#x20;   └── index.html    # Web interface

```



\## Future Improvements



\- IP reputation lookup using AbuseIPDB

\- File hash lookup using VirusTotal

\- Domain age check using WHOIS

\- Export results as a report



\## Author



Bhawna (\[github.com/Bhawna45](https://github.com/Bhawna45))



