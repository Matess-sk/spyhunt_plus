Môžeš použiť tento markdown súbor `README.md` priamo pre GitHub:

````markdown
# SpyHunt+

**SpyHunt+** je OSINT a web-recon toolkit pre penetračné testovanie a bug bounty.  
Implementuje množstvo modulov na zber informácií, enumeráciu, analýzu a jednoduché testy zraniteľností.  
Používaj **iba na ciele, na ktoré máš povolenie**.

---

## 📦 Inštalácia

**Požiadavky:**
- Python 3.10+
- Linux/macOS/Windows
- API kľúče pre niektoré integrácie (Shodan, SerpAPI)

```bash
# Povinné
pip install httpx

# Odporúčané
pip install dnspython mmh3

# Voliteľné externé nástroje
sudo apt install nmap nuclei  # alebo ekvivalent pre tvoj OS

# API kľúče (voliteľné)
export SHODAN_API_KEY="tvoj_shodan_api_key"
export SERPAPI_KEY="tvoj_serpapi_api_key"
````

---

## 🚀 Použitie

Formát príkazu:

```bash
python3 spyhunt_plus.py [globálne voľby] <príkaz> [argumenty]
```

Globálne voľby:

* `-o FILE` — výstupný JSONL súbor (default: `spyhunt_plus.jsonl`)
* `--rps N` — limit požiadaviek za sekundu
* `--header "Key: Value"` — vlastná HTTP hlavička (možno opakovať)

---

## 📚 Príkazy

| Príkaz       | Popis                                                                                                 |
| ------------ | ----------------------------------------------------------------------------------------------------- |
| `autorecon`  | Spustí CMS detekciu, CVE lookup, security headers, crawling, broken link check, favicon hash, fuzzing |
| `cms`        | Deteguje CMS, verziu a nájde online CVE                                                               |
| `subdomains` | Enumeruje subdomény zo wordlistu                                                                      |
| `dns`        | Zistí DNS záznamy                                                                                     |
| `crawl`      | Web crawling a extrakcia URL a JS súborov                                                             |
| `favicon`    | Stiahne favicon.ico a spočíta mmh3 hash                                                               |
| `hosttest`   | Test Host header injection                                                                            |
| `secheads`   | Analýza security hlavičiek                                                                            |
| `wayback`    | Získa URL z Wayback Machine                                                                           |
| `broken`     | Overí zoznam URL na 404 a chyby                                                                       |
| `smuggle`    | Test na HTTP request smuggling                                                                        |
| `dirb`       | Directory/file brute-force                                                                            |
| `ports`      | Port scan alebo CIDR scan                                                                             |
| `nmap`       | Spustí nmap (ak je v PATH)                                                                            |
| `nuclei`     | Spustí nuclei (ak je v PATH)                                                                          |
| `shodan`     | Vyhľadá informácie o IP/doméne cez Shodan                                                             |
| `dork`       | Google dorking cez SerpAPI                                                                            |
| `s3`         | AWS S3 bucket enumerácia                                                                              |
| `fuzz`       | Heuristický test XSS, SQLi a traversal                                                                |

---

## 🔍 Príklady

```bash
# AutoRecon na cieľ
python3 spyhunt_plus.py autorecon https://example.com -o out.jsonl

# Detekcia CMS a CVE
python3 spyhunt_plus.py cms https://example.com -o out.jsonl

# Enumerácia subdomén
python3 spyhunt_plus.py subdomains example.com -w subs.txt -o out.jsonl

# DNS záznamy
python3 spyhunt_plus.py dns example.com -t MX -o out.jsonl

# Directory brute-force
python3 spyhunt_plus.py dirb https://example.com -w paths.txt -o out.jsonl

# Port scan (top porty)
python3 spyhunt_plus.py ports 93.184.216.34 --top -o out.jsonl

# Shodan lookup
python3 spyhunt_plus.py shodan 1.2.3.4 -o out.jsonl
```

---

## 📄 Výstup

* Výstup je vo formáte **JSONL** (jeden riadok = jeden JSON objekt).
* Jednoduché spracovanie cez `jq`:

```bash
jq '.module, .target' out.jsonl
```

---

## ⚠️ Upozornenie

Tento nástroj je určený výhradne na legálne penetračné testovanie a OSINT.
Autor nezodpovedá za žiadne zneužitie.

---
inspirovane: https://github.com/gotr00t0day/spyhunt/tree/main
