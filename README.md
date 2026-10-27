# Password Strength Analyzer & Secure Hashing Tool

A single-page web app that measures password strength in real time and demonstrates secure hashing.
It is 100% client-side (HTML, CSS, JavaScript): nothing you type leaves your browser.

**Live demo:** https://YOUR-USERNAME.github.io/password-analyzer-web/

## Features
- Real-time strength meter: entropy, color-coded bar, 0-100 score
- Pattern detection: sequences, keyboard walks, repeats, years, leetspeak, common passwords
- Crack-time estimates for online, slow-hash and fast-hash attackers
- Secure password generator (`crypto.getRandomValues`, unbiased)
- Hashing tool: MD5 (demo), SHA-1, SHA-256, SHA-384, SHA-512, salted SHA-256, PBKDF2-SHA256
- Hash verification with constant-time comparison
- Security Lab: salting demo, avalanche effect, slow-hash speed test

## Run locally
Open `index.html` in a browser, or serve it:

    python -m http.server 8000

then visit http://localhost:8000

## Files
- `index.html` structure and Content-Security-Policy
- `style.css` styling
- `script.js` analysis engine, hashing (Web Crypto API), UI

## Security design
- Content-Security-Policy blocks all network access (`connect-src 'none'`) and inline scripts
- User text is only ever inserted with `textContent`, never `innerHTML`
- Salts and passwords come from `crypto.getRandomValues`, not `Math.random`
- Verification limits PBKDF2 iterations to 2,000,000 so a pasted hash cannot freeze the page

## Limitations
Entropy is an estimate; ordinary-word passphrases are over-estimated; the wordlist is small;
browsers do not provide Argon2 or bcrypt, so PBKDF2 is the slow hash used here.

## License
MIT
