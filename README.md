# 🛡️ LinkTruth — URL Forensic Analyzer

**Is that link real, or a trap?**
LinkTruth is a privacy-focused, browser-based tool that inspects URLs for phishing signatures, spoofing attempts, and malicious patterns without ever sending your data to a server.

![HTML5](https://img.shields.io/badge/HTML5-E34F26?style=for-the-badge&logo=html5&logoColor=white)
![CSS3](https://img.shields.io/badge/CSS3-1572B6?style=for-the-badge&logo=css3&logoColor=white)
![JavaScript](https://img.shields.io/badge/JavaScript-F7DF1E?style=for-the-badge&logo=javascript&logoColor=black)
![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)

## 🚀 Features

LinkTruth runs **20+ forensic checks** entirely in your browser:

*   **Protocol Integrity:** Detects dangerous schemes like `data:` or `javascript:`.
*   **Domain Forensics:** Identifies raw IP addresses, deep subdomain chains, and Punycode homograph attacks.
*   **Brand Impersonation:** Uses **Levenshtein distance** and **Leet-speak decoding** (e.g., `paypa1` → `paypal`) to spot typosquatting.
*   **TLD Reputation:** Flags high-abuse Top-Level Domains (like `.tk`, `.xyz`, `.gq`) often used in scams.
*   **Cloaking Detection:** Spots URL shorteners, `@` decoys, and suspicious ports.
*   **Payload Hints:** Warns about executable downloads (`.exe`, `.scr`) and urgency keyword stuffing.

## 🔒 Privacy First
Unlike other scanners, **LinkTruth does not upload your URL to any server**. The analysis engine runs 100% locally on your device using JavaScript. Your links never leave your browser.

## 🛠️ Tech Stack
*   **Frontend:** HTML5, CSS3 (Grid/Flexbox)
*   **Logic:** Vanilla JavaScript (ES6+)
*   **No Backend:** Zero server dependencies

## 📂 Project Structure
*   `index.html` — Main UI and layout
*   `style.css` — Dark mode styling and animations
*   `script.js` — The core heuristic analysis engine

 ## Scan Here  https://anithaamaravadi.github.io/Link-Truth/
