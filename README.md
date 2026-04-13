<div align="center">

# 🦄 Unicorn Scanner

**Open-source website intelligence and security reconnaissance tool**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-unicorn--d2n.pages.dev-7c3aed?style=for-the-badge&logo=cloudflare&logoColor=white)](https://unicorn-d2n.pages.dev)
[![Built with React](https://img.shields.io/badge/React-18-61DAFB?style=for-the-badge&logo=react&logoColor=black)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org)
[![Cloudflare Pages](https://img.shields.io/badge/Deployed%20on-Cloudflare%20Pages-F38020?style=for-the-badge&logo=cloudflare&logoColor=white)](https://pages.cloudflare.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

*The reconnaissance tool you actually want to use — fast, web-based, and free.*

![Unicorn Scanner Screenshot](https://unicorn-d2n.pages.dev/og-preview.png)

</div>

---

## What is Unicorn Scanner?

Unicorn Scanner is a **free, open-source web-based reconnaissance tool** that gives you a comprehensive intelligence report on any website — in seconds. Think of it as having `whois`, `nmap`, `wpscan`, `whatmydns`, and `who.is` all rolled into one clean interface, accessible from any browser with no installation required.

Built for security researchers, web developers, and digital agencies who need fast, reliable website intelligence without switching between a dozen different tools.

> ⚠️ **For authorized use only.** Always ensure you have explicit permission before scanning any website. Unauthorized scanning may be illegal in your jurisdiction.

---

## 🚀 Live Demo

**[https://unicorn-d2n.pages.dev](https://unicorn-d2n.pages.dev)**

No sign-up. No API key. Just enter a URL and scan.

---

## 🔍 What It Scans (16 modules, all in parallel)

### 🌐 Core Checks
| Module | Details |
|--------|---------|
| **Online Status** | HTTP status code, response time, live/offline detection |
| **Performance** | Page load time, transfer size, KB/s |
| **SSL Certificate** | Issuer, expiry date, days remaining, TLS version, SANs, fingerprint |
| **HTTP Headers** | Full header dump + security header scorecard (HSTS, CSP, X-Frame-Options, etc.) |

### 🌍 Network & DNS
| Module | Details |
|--------|---------|
| **IP & Geolocation** | City, country, ISP, ASN, coordinates, timezone |
| **DNS Records** | A, AAAA, MX, NS, TXT, CAA, SOA |
| **DNS Propagation** | A record checked across 7 global resolvers (Google, Cloudflare, Quad9, OpenDNS, AdGuard, NextDNS, Comcast) — like whatmydns |
| **WHOIS** | Registrar, registrant details, contacts, created/expiry/updated dates, DNSSEC status |

### 📧 Email & Security
| Module | Details |
|--------|---------|
| **Email Security** | SPF record, DMARC policy, DKIM selector detection |
| **Security Checks** | Exposed `.git`, `.env`, `phpinfo.php`, `backup.zip`, `readme.html`, xmlrpc, admin panels |
| **Cookies** | Name, HttpOnly, Secure, SameSite flags for every cookie |

### 🎯 Intelligence
| Module | Details |
|--------|---------|
| **Meta / SEO** | Title, description, keywords, Open Graph tags, Twitter Card, Schema.org, canonical URL |
| **Tech Stack** | 35+ technology fingerprints — frameworks, CMS, analytics, CDN, payments |
| **Common Files** | `robots.txt`, `sitemap.xml` (with URL count), `security.txt`, `ads.txt`, `humans.txt` |
| **Socials & Emails** | Email addresses and social media profile links extracted from page HTML |

### 🔷 WordPress Deep Scan
| Feature | Details |
|---------|---------|
| **Core Version** | Detected from meta generator or `readme.html` |
| **Theme Details** | Name, version, author, URI, description — parsed from `style.css` |
| **Plugin Audit** | Every plugin detected, with **installed version vs latest version** from WordPress.org API, flagging outdated plugins in red |
| **Username Security** | Weak username detection (`admin`, `administrator`, `root`, etc.), REST API exposure (`/wp-json/wp/v2/users`), author enumeration via `/?author=N` redirects |
| **Exposure Checks** | `xmlrpc.php`, `readme.html`, REST API enabled/disabled |

---

## 🛡️ Security First

Unicorn Scanner was designed with security at its core — not just for scanning others, but in how it's built:

- **No shell injection** — zero `exec()` or `eval()` with user input
- **WHOIS via TCP** — direct socket connection, no shell commands
- **Private IP blocking** — SSRF protection, localhost/RFC1918 ranges rejected
- **Rate limiting** — 10 scans per 15 minutes per IP
- **Consent required** — users must confirm authorization before every scan
- **Helmet.js** — security headers on all API responses

---

## 🏗️ Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | React 18 + TypeScript + Tailwind CSS |
| Build | Vite |
| API (production) | Cloudflare Pages Functions (Workers runtime) |
| API (local/self-hosted) | Node.js + Express |
| DNS lookups | DNS-over-HTTPS (Cloudflare / Google DoH) |
| WHOIS | Direct TCP socket to WHOIS servers |
| SSL | Node.js `tls` module |
| Deployment | Cloudflare Pages / Netlify |

---

## 🚢 Deploy Your Own

### Cloudflare Pages (recommended — free)

1. Fork this repo
2. Go to [Cloudflare Pages](https://pages.cloudflare.com) → Create → Pages → Connect to Git
3. Select your fork
4. Set **Build command:** `npm run build` · **Output directory:** `dist`
5. Leave **Deploy command** blank
6. Deploy

Cloudflare auto-discovers `functions/api/scan.js` and serves it at `/api/scan`.

### Netlify (alternative — free)

1. Fork this repo
2. Go to [Netlify](https://netlify.com) → Add new site → Import from Git
3. Select your fork — `netlify.toml` handles everything automatically
4. Deploy

### Local Development

```bash
git clone https://github.com/davidjenner/Unicorn.git
cd Unicorn
npm install

# Run both server and client in parallel
npm run dev
```

The React dev server runs on `http://localhost:5173` and proxies `/api` to the Express server on `:5000`.

---

## 📁 Project Structure

```
├── src/
│   ├── App.tsx              # React UI — all 16 result cards
│   └── main.tsx             # Entry point
├── functions/
│   └── api/scan.js          # Cloudflare Pages Function (fetch-based)
├── lib/
│   └── scanner.js           # Shared Node.js scan logic (Express / Netlify)
├── netlify/
│   └── functions/scan.js    # Netlify serverless handler
├── server.js                # Express server (local dev / self-hosted)
├── netlify.toml             # Netlify build + redirect config
└── wrangler.toml            # Cloudflare Pages config
```

---

## 🗺️ Roadmap

- [ ] PDF / JSON export of scan results
- [ ] Scan history (saved locally)
- [ ] Subdomain enumeration
- [ ] Port scanning (common ports)
- [ ] Broken link checker
- [ ] Email address harvesting (deeper crawl)
- [ ] API endpoint for programmatic access
- [ ] Dark/light theme toggle

Got a feature request? [Open an issue](https://github.com/davidjenner/Unicorn/issues).

---

## 🤝 Contributing

Contributions are welcome. Please open an issue first to discuss what you'd like to change, then submit a pull request.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes
4. Push and open a PR

---

## 👨‍💻 Author

**David Jenner**
🔗 [linkedin.com/in/davidjenner6](https://www.linkedin.com/in/davidjenner6)
🐙 [github.com/davidjenner](https://github.com/davidjenner)

---

## ⭐ Support the Project

If Unicorn Scanner saved you time, consider giving the repo a star — it helps others find it.

[![Star on GitHub](https://img.shields.io/github/stars/davidjenner/Unicorn?style=for-the-badge&logo=github&logoColor=white&color=7c3aed)](https://github.com/davidjenner/Unicorn/stargazers)

---

## ☕ Buy Me a Coffee

If this tool genuinely helped you and you'd like to support its development:

<a href="https://www.buymeacoffee.com/godavid" target="_blank">
  <img src="https://img.shields.io/badge/Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buy-me-a-coffee&logoColor=black" alt="Buy Me A Coffee" />
</a>

Every coffee keeps the scanner running and the features coming. 🦄

---

## 📄 License

MIT © [David Jenner](https://github.com/davidjenner)

*Use it, fork it, build on it — just don't scan systems you don't own.*
