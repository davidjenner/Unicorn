'use strict';

/**
 * Unicorn Scanner — shared scan logic.
 * Pure Node.js, no shell exec. Works in Lambda (Netlify) and local Express.
 */

const axios = require('axios');
const dns   = require('dns').promises;
const tls   = require('tls');
const net   = require('net');
const { URL } = require('url');

// ── URL Validation ────────────────────────────────────────────────────────────

const PRIVATE_PATTERNS = [
  /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^0\.0\.0\.0/, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i,
];

function validateUrl(rawUrl) {
  let parsed;
  try {
    const s = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    parsed = new URL(s);
  } catch { return { valid: false, error: 'Invalid URL format.' }; }

  if (!['http:', 'https:'].includes(parsed.protocol))
    return { valid: false, error: 'Only HTTP and HTTPS URLs are supported.' };

  if (PRIVATE_PATTERNS.some(p => p.test(parsed.hostname)))
    return { valid: false, error: 'Scanning private or local addresses is not permitted.' };

  if (!/^[a-zA-Z0-9.\-]+$/.test(parsed.hostname))
    return { valid: false, error: 'Hostname contains invalid characters.' };

  return { valid: true, hostname: parsed.hostname, url: parsed.href };
}

// ── Axios helpers ─────────────────────────────────────────────────────────────

const UA      = 'Mozilla/5.0 (compatible; UnicornScanner/2.0)';
const TIMEOUT = 15000;

const axiosHead = (url) =>
  axios.head(url, { timeout: TIMEOUT, headers: { 'User-Agent': UA }, maxRedirects: 5, validateStatus: () => true });

const axiosGet = (url, maxBytes = 2 * 1024 * 1024) =>
  axios.get(url, { timeout: TIMEOUT, headers: { 'User-Agent': UA }, maxRedirects: 5,
    maxContentLength: maxBytes, validateStatus: () => true, responseType: 'text' });

// ── WHOIS via TCP (no shell) ──────────────────────────────────────────────────

const WHOIS_SERVERS = {
  com: 'whois.verisign-grs.com', net: 'whois.verisign-grs.com', org: 'whois.pir.org',
  io: 'whois.nic.io', co: 'whois.nic.co', uk: 'whois.nic.uk', 'co.uk': 'whois.nic.uk',
  de: 'whois.denic.de', fr: 'whois.nic.fr', nl: 'whois.domain-registry.nl',
  au: 'whois.auda.org.au', ca: 'whois.cira.ca', eu: 'whois.eu',
  info: 'whois.afilias.net', biz: 'whois.biz', us: 'whois.nic.us',
  dev: 'whois.nic.google', app: 'whois.nic.google', ai: 'whois.nic.ai',
};

function whoisTcp(domain) {
  const parts = domain.split('.');
  const tld   = parts.slice(-2).join('.').toLowerCase();
  const tld1  = parts[parts.length - 1].toLowerCase();
  const server = WHOIS_SERVERS[tld] || WHOIS_SERVERS[tld1] || `whois.nic.${tld1}`;

  return new Promise((resolve) => {
    const socket = net.createConnection({ host: server, port: 43 });
    let data = '';
    socket.setTimeout(12000);
    socket.on('connect', () => { socket.write(`${domain}\r\n`); });
    socket.on('data',    (chunk) => { data += chunk; });
    socket.on('end',     () => resolve(data));
    socket.on('error',   (err) => resolve(`Error: ${err.message}`));
    socket.on('timeout', () => { socket.destroy(); resolve('Error: timeout'); });
  });
}

// ── Scan modules ──────────────────────────────────────────────────────────────

async function checkOnline(url) {
  const start = Date.now();
  try {
    const r = await axiosHead(url);
    return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
  } catch {
    try {
      const r = await axiosGet(url, 512 * 1024);
      return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
    } catch (err) { return { error: err.message }; }
  }
}

async function getHeaders(url) {
  try {
    const r = await axiosHead(url);
    const h = r.headers;
    const SEC = [
      'strict-transport-security', 'content-security-policy', 'x-frame-options',
      'x-content-type-options', 'referrer-policy', 'permissions-policy',
    ];
    const present = SEC.filter(k => !!h[k]);
    const interesting = {};
    for (const key of [
      'server', 'x-powered-by', 'content-type', 'via', 'cf-ray', 'x-varnish',
      'x-cache', 'age', 'cache-control', 'x-generator', ...SEC,
    ]) { if (h[key]) interesting[key] = h[key]; }
    return {
      headers: interesting,
      securityHeaders: Object.fromEntries(SEC.map(k => [k, !!h[k]])),
      securityScore: `${present.length}/${SEC.length}`,
    };
  } catch (err) { return { error: err.message }; }
}

async function getSSL(hostname) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      { host: hostname, port: 443, servername: hostname, rejectUnauthorized: false, timeout: 10000 },
      () => {
        const cert = socket.getPeerCertificate(true);
        const proto = socket.getProtocol ? socket.getProtocol() : 'unknown';
        socket.destroy();
        if (!cert || !cert.subject) { resolve({ error: 'No certificate found' }); return; }
        const daysRemaining = Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000);
        resolve({
          subject: cert.subject, issuer: cert.issuer,
          validFrom: cert.valid_from, validTo: cert.valid_to,
          daysRemaining, fingerprint: cert.fingerprint,
          protocol: proto, expired: daysRemaining < 0,
        });
      }
    );
    socket.on('error', err => resolve({ error: err.message }));
    socket.setTimeout(10000, () => { socket.destroy(); resolve({ error: 'Connection timed out' }); });
  });
}

async function getDNS(hostname) {
  const result = {};
  await Promise.allSettled([
    dns.resolve4(hostname).then(r => { result.A    = r; }).catch(() => {}),
    dns.resolve6(hostname).then(r => { result.AAAA = r; }).catch(() => {}),
    dns.resolveMx(hostname).then(r => { result.MX  = r; }).catch(() => {}),
    dns.resolveNs(hostname).then(r => { result.NS  = r; }).catch(() => {}),
    dns.resolveTxt(hostname).then(r => { result.TXT = r.map(a => a.join('')); }).catch(() => {}),
  ]);
  return result;
}

async function getWhois(hostname) {
  const domain = hostname.replace(/^www\./, '');
  const raw = await whoisTcp(domain);
  if (raw.startsWith('Error:')) return { error: raw };
  const pick = (re) => { const m = raw.match(re); return m ? m[1].trim() : null; };
  return {
    registrar:         pick(/^Registrar:\s*(.+)/im),
    createdDate:       pick(/Creation Date:\s*(.+)/i),
    expiryDate:        pick(/Registry Expiry Date:\s*(.+)/i),
    updatedDate:       pick(/Updated Date:\s*(.+)/i),
    registrantOrg:     pick(/Registrant Organization:\s*(.+)/i),
    registrantCountry: pick(/Registrant Country:\s*(.+)/i),
    nameServers: [...new Set(
      (raw.match(/Name Server:\s*(.+)/gi) || []).map(s => s.replace(/Name Server:\s*/i, '').trim().toLowerCase())
    )].slice(0, 6),
    status: (raw.match(/Domain Status:\s*(\S+)/gi) || [])
      .map(s => s.replace(/Domain Status:\s*/i, '').trim()).slice(0, 4),
  };
}

async function getPerformance(url) {
  const start = Date.now();
  try {
    const r = await axiosGet(url, 5 * 1024 * 1024);
    const totalTime = Date.now() - start;
    const size = typeof r.data === 'string' ? Buffer.byteLength(r.data) : 0;
    return {
      totalTime, httpCode: r.status, size,
      sizeKB: (size / 1024).toFixed(1),
      transferRate: size > 0 ? ((size / 1024) / (totalTime / 1000)).toFixed(1) : null,
    };
  } catch (err) { return { error: err.message }; }
}

async function detectWordPress(url) {
  try {
    const [htmlRes, versionRes] = await Promise.allSettled([
      axiosGet(url, 2 * 1024 * 1024),
      axiosGet(`${url.replace(/\/$/, '')}/wp-includes/version.php`, 64 * 1024),
    ]);
    const html   = htmlRes.status === 'fulfilled' ? (htmlRes.value.data || '') : '';
    const wpHit  = versionRes.status === 'fulfilled' && versionRes.value.status === 200;
    const isWP   = html.includes('wp-content') || html.includes('wp-includes') || wpHit;
    if (!isWP) return { detected: false };

    const verMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9.]+)/i);
    const plugins  = [...new Set([...html.matchAll(/wp-content\/plugins\/([a-z0-9\-_]+)/gi)].map(m => m[1]))].slice(0, 25);
    const themeMatch = html.match(/wp-content\/themes\/([a-z0-9\-_]+)/i);
    return { detected: true, version: verMatch ? verMatch[1] : null, plugins, theme: themeMatch ? themeMatch[1] : null };
  } catch (err) { return { error: err.message }; }
}

async function getCookies(url) {
  try {
    const r = await axiosHead(url);
    const raw = r.headers['set-cookie'] || [];
    const cookies = raw.map(cookie => {
      const parts = cookie.split(';').map(p => p.trim());
      const flags = parts.slice(1).map(f => f.toLowerCase());
      return {
        name:     parts[0].split('=')[0],
        httpOnly: flags.includes('httponly'),
        secure:   flags.includes('secure'),
        sameSite: flags.find(f => f.startsWith('samesite='))?.split('=')[1] || null,
      };
    });
    return { cookies, count: cookies.length };
  } catch (err) { return { error: err.message }; }
}

async function getTechStack(url) {
  try {
    const [htmlRes, headRes] = await Promise.allSettled([
      axiosGet(url, 2 * 1024 * 1024), axiosHead(url),
    ]);
    const html    = htmlRes.status === 'fulfilled' ? (htmlRes.value.data || '') : '';
    const headers = headRes.status  === 'fulfilled' ? headRes.value.headers : {};
    const tech = [];
    if (headers.server)        tech.push({ name: headers.server,           category: 'Web Server' });
    if (headers['x-powered-by']) tech.push({ name: headers['x-powered-by'], category: 'Runtime' });
    if (headers['cf-ray'])     tech.push({ name: 'Cloudflare',             category: 'CDN / Security' });
    if (headers['x-varnish'])  tech.push({ name: 'Varnish Cache',          category: 'Cache' });
    const patterns = [
      [/_next\//i,                  'Next.js',          'JS Framework'],
      [/react(?:\.js|dom)/i,        'React',            'JS Framework'],
      [/vue(?:\.js|\.min\.js)/i,    'Vue.js',           'JS Framework'],
      [/angular(?:\.js|\/)/i,       'Angular',          'JS Framework'],
      [/nuxt/i,                     'Nuxt.js',          'JS Framework'],
      [/svelte/i,                   'Svelte',           'JS Framework'],
      [/jquery(?:\.min)?\.js/i,     'jQuery',           'JS Library'],
      [/bootstrap(?:\.min)?\.css/i, 'Bootstrap',        'CSS Framework'],
      [/tailwind/i,                 'Tailwind CSS',     'CSS Framework'],
      [/wp-content/i,               'WordPress',        'CMS'],
      [/drupal/i,                   'Drupal',           'CMS'],
      [/joomla/i,                   'Joomla',           'CMS'],
      [/shopify/i,                  'Shopify',          'E-commerce'],
      [/woocommerce/i,              'WooCommerce',      'E-commerce'],
      [/squarespace/i,              'Squarespace',      'Website Builder'],
      [/webflow/i,                  'Webflow',          'Website Builder'],
      [/gatsby/i,                   'Gatsby',           'Static Site'],
      [/gtag\(|google-analytics/i,  'Google Analytics', 'Analytics'],
    ];
    for (const [pattern, name, category] of patterns)
      if (pattern.test(html)) tech.push({ name, category });
    return { technologies: [...new Map(tech.map(t => [t.name, t])).values()] };
  } catch (err) { return { error: err.message }; }
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

async function runScan(rawUrl) {
  const v = validateUrl(rawUrl);
  if (!v.valid) return { error: v.error };

  const settle = r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message || 'Failed' };

  const [online, headers, ssl, dnsRec, whois, perf, wp, cookies, techStack] =
    await Promise.allSettled([
      checkOnline(v.url),
      getHeaders(v.url),
      getSSL(v.hostname),
      getDNS(v.hostname),
      getWhois(v.hostname),
      getPerformance(v.url),
      detectWordPress(v.url),
      getCookies(v.url),
      getTechStack(v.url),
    ]);

  return {
    url:         v.url,
    hostname:    v.hostname,
    timestamp:   new Date().toISOString(),
    online:      settle(online),
    headers:     settle(headers),
    ssl:         settle(ssl),
    dns:         settle(dnsRec),
    whois:       settle(whois),
    performance: settle(perf),
    wordpress:   settle(wp),
    cookies:     settle(cookies),
    techStack:   settle(techStack),
  };
}

module.exports = { runScan, validateUrl };
