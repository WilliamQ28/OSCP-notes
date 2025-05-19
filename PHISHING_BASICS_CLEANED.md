# Phishing Basics

Phishing refers to techniques that run malicious code or steal login credentials, often via social engineering and manipulation.

---

## Types of Phishing

### Email Phishing
- Most traditional and common method.
- Goal: Convince the target to perform an action that executes malicious code.
- Techniques:
  - Malicious attachments (e.g., PDF, ZIP/7z shortcut files, calendar invites).
  - Embedded links leading to exploit-laden websites.
  - Pharming: Redirecting users to fraudulent websites.
- Pretext: A believable fake story to gain trust.
- Indicators:
  - Typos, bad grammar, formatting errors.
  - Solid social engineering with OSINT collection.
  - Use of familiar domains or look-alike domains.
  - Email from a legitimate or expected source increases success.
- Whaling: High-level individuals targeted; requires insider knowledge.

### Smishing, Vishing, and Chatting
- **Smishing**: SMS-based phishing. Personal and direct.
- **Vishing**: Voice-based phishing. Requires social engineering.
  - Caller ID spoofing and VoIP targeting.
  - SIM swapping to bypass phone-based MFA.
- **Chat-based Phishing**: Performed on apps like Discord, Slack, Teams.

---

## Social Engineering Tactics

- Psychological manipulation over technical exploitation.
- Trust is the end goal.
- **Urgency**: Forces quick, uncritical action.
- **Fear and Authority**: Suspend judgment.
- **Pavlovian Tactics**: Build rapport through repeated trust cues.

---

## AI and Deepfakes

- **Retrieval-Augmented Generation (RAG)**: Craft convincing pretexts with public data.
- **Voice Cloning**: Mimicking voices (e.g., meme versions).
- **Deepfake Videos**: Require significant computing power; increasingly regulated.

---

## Email Filter Defenses

- Inbound email filters scan for malicious markers.
- Consider domain reputation (via blocklists).
- Scan file attachments (e.g., EXE, SCR).
- External domain markers for awareness.

---

## Malicious Office Macros

- MS Office supports Visual Basic for Applications (VBA).
- **Mark of the Web (MotW)**: Indicates files from external sources.
- **Protected View**: Warns users before running external documents.
- **Admin Controls**: Enforced through Active Directory Group Policy.
- Note: Many orgs still use outdated Office versions.

---

## Malicious File Threats

- Common payloads:
  - EXE, SCR, HTA, JScript.
  - Ancillary Office documents to bypass mainstream filters.
  - PDFs are commonly targeted.
- Advanced attacks may leverage known vulnerabilities (N-days) or undisclosed ones (0-days).

---

## Malicious Links

- **Credential Harvesting**:
  - Cloning services like Gmail, Zoom, Microsoft Login.
  - Password managers may flag improper domains.
  - Some managers can be tricked (e.g., LastPass via crafted URLs).
- **Browser Exploits**:
  - Advanced, rare without 0-days.
- **CSRF**:
  - Exploit existing sessions to make unintended requests.
- **Link Obfuscation**:
  - Use of shorteners (TinyURL, Bitly).
  - Homograph attacks using similar-looking characters.
- HTTPS is essential for credibility.

---

## MFA and Credential Phishing

- **MFA Prompt Bombing**: Repeated login prompts cause user fatigue.
- **Inline MFA Capture**: Built into phishing site to steal tokens.
- **Browser-in-the-Middle (BitM)**: Proxy real sessions to capture data (e.g., Cuddlephish).
- **Brute Force**: MFA codes (usually 6 digits) guessed.
- **Social Engineering**: Bypasses MFA through user trickery.

---

## Zoom Phishing Pretext (Example)

1. Read sample outgoing mail to match tone and style.
2. Use ChatGPT to replicate tone and embed a fake Zoom link.

```text
Looking at the following email:
<original_email>
Write another email in the same style as this, and include a reminder for employees to log in to Zoom. Include a hyperlink.
```

---

## Cloning Legitimate Sites

1. Search for target (e.g., Zoom sign-in).
2. Create working directory:

```bash
mkdir ZoomSignin
cd ZoomSignin
```

3. Clone with `wget`:

```bash
wget -E -k -K -p -e robots=off -H -D<domain> -nd <URL>
```

---

## Cleanup and Injection

1. Remove CSRF alerts:

```bash
grep "OWASP" *
# Edit out identified line from the HTML file.
```

2. Deploy to Web Server:

```bash
mv -f * /var/www/html
systemctl start apache2
cd /var/www/html
cp -f signin.html signin_orig.html
```

3. Inject Credentials Capture:

```bash
sudo echo "" > credentials.txt
sudo chmod 777 custom_login.php
sudo chmod 777 credentials.txt
```

Inspect and modify the form inputs. Ask ChatGPT to help rewrite dynamically generated HTML code if needed.

---
