/**
 * Cloudflare Pages Function — /api/scan
 * Uses Workers runtime: fetch API + Cloudflare DNS-over-HTTPS.
 * No Node.js built-ins required.
 */

const UA      = 'Mozilla/5.0 (compatible; UnicornScanner/2.0)';
const TIMEOUT = 15000;

// ── URL validation ────────────────────────────────────────────────────────────

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

// ── fetch with timeout ────────────────────────────────────────────────────────

function fetchTimeout(url, opts = {}, ms = TIMEOUT) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...opts, signal: controller.signal })
    .finally(() => clearTimeout(timer));
}

// ── Scan modules ──────────────────────────────────────────────────────────────

async function checkOnline(url) {
  const start = Date.now();
  try {
    const r = await fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA }, redirect: 'follow' });
    return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
  } catch {
    try {
      const r = await fetchTimeout(url, { method: 'GET', headers: { 'User-Agent': UA }, redirect: 'follow' });
      return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
    } catch (err) { return { error: err.message }; }
  }
}

async function getHeaders(url) {
  try {
    const r = await fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA }, redirect: 'follow' });
    const SEC = [
      'strict-transport-security', 'content-security-policy', 'x-frame-options',
      'x-content-type-options', 'referrer-policy', 'permissions-policy',
    ];
    const INTERESTING = ['server','x-powered-by','content-type','via','cf-ray','x-varnish','x-cache','age','cache-control','x-generator',...SEC];
    const headers = {};
    for (const k of INTERESTING) { const v = r.headers.get(k); if (v) headers[k] = v; }
    const securityHeaders = Object.fromEntries(SEC.map(k => [k, !!r.headers.get(k)]));
    const present = SEC.filter(k => !!r.headers.get(k));
    return { headers, securityHeaders, securityScore: `${present.length}/${SEC.length}` };
  } catch (err) { return { error: err.message }; }
}

async function getSSL(hostname) {
  // Workers can't inspect TLS certs directly; infer from HTTPS availability
  try {
    const r = await fetchTimeout(`https://${hostname}`, { method: 'HEAD', headers: { 'User-Agent': UA } });
    return {
      note: 'Full certificate details require server-side TLS inspection.',
      httpsReachable: r.ok || r.status < 500,
      status: r.status,
    };
  } catch (err) {
    return { error: err.message, httpsReachable: false };
  }
}

async function getDNS(hostname) {
  // Cloudflare DNS-over-HTTPS (1.1.1.1)
  const DOH = 'https://cloudflare-dns.com/dns-query';
  const types = ['A', 'AAAA', 'MX', 'NS', 'TXT'];
  const result = {};

  await Promise.allSettled(types.map(async (type) => {
    try {
      const r = await fetchTimeout(
        `${DOH}?name=${encodeURIComponent(hostname)}&type=${type}`,
        { headers: { Accept: 'application/dns-json' } }
      );
      const data = await r.json();
      if (!data.Answer) return;
      if (type === 'MX') {
        result.MX = data.Answer.map(a => {
          const [priority, exchange] = a.data.split(' ');
          return { priority: Number(priority), exchange };
        });
      } else if (type === 'TXT') {
        result.TXT = data.Answer.map(a => a.data.replace(/"/g, ''));
      } else {
        result[type] = data.Answer.map(a => a.data);
      }
    } catch {}
  }));

  return result;
}

async function getWhois(hostname) {
  // Public WHOIS REST API (no TCP sockets needed in Workers)
  const domain = hostname.replace(/^www\./, '');
  try {
    const r = await fetchTimeout(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { headers: { Accept: 'application/json' } }
    );
    if (!r.ok) return { error: `RDAP returned ${r.status}` };
    const data = await r.json();

    const getEvent = (action) =>
      data.events?.find(e => e.eventAction === action)?.eventDate ?? null;

    const registrar = data.entities?.find(e => e.roles?.includes('registrar'));
    const registrant = data.entities?.find(e => e.roles?.includes('registrant'));
    const registrantOrg = registrant?.vcardArray?.[1]?.find(f => f[0] === 'org')?.[3] ?? null;
    const registrantCountry = registrant?.vcardArray?.[1]?.find(f => f[0] === 'adr')?.[1]?.['country-name'] ?? null;

    return {
      registrar:         registrar?.vcardArray?.[1]?.find(f => f[0] === 'fn')?.[3] ?? null,
      createdDate:       getEvent('registration'),
      expiryDate:        getEvent('expiration'),
      updatedDate:       getEvent('last changed'),
      registrantOrg,
      registrantCountry,
      nameServers:       (data.nameservers || []).map(ns => ns.ldhName?.toLowerCase()).filter(Boolean).slice(0, 6),
      status:            (data.status || []).slice(0, 4),
    };
  } catch (err) { return { error: err.message }; }
}

async function getPerformance(url) {
  const start = Date.now();
  try {
    const r = await fetchTimeout(url, { method: 'GET', headers: { 'User-Agent': UA }, redirect: 'follow' }, 30000);
    const text = await r.text();
    const totalTime = Date.now() - start;
    const size = new TextEncoder().encode(text).length;
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
      fetchTimeout(url, { headers: { 'User-Agent': UA } }),
      fetchTimeout(`${url.replace(/\/$/, '')}/wp-includes/version.php`, { headers: { 'User-Agent': UA } }),
    ]);
    const html  = htmlRes.status === 'fulfilled' ? await htmlRes.value.text() : '';
    const wpHit = versionRes.status === 'fulfilled' && versionRes.value.status === 200;
    const isWP  = html.includes('wp-content') || html.includes('wp-includes') || wpHit;
    if (!isWP) return { detected: false };

    const verMatch   = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9.]+)/i);
    const plugins    = [...new Set([...html.matchAll(/wp-content\/plugins\/([a-z0-9\-_]+)/gi)].map(m => m[1]))].slice(0, 25);
    const themeMatch = html.match(/wp-content\/themes\/([a-z0-9\-_]+)/i);
    return { detected: true, version: verMatch ? verMatch[1] : null, plugins, theme: themeMatch ? themeMatch[1] : null };
  } catch (err) { return { error: err.message }; }
}

async function getCookies(url) {
  try {
    const r = await fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA }, redirect: 'follow' });
    // Workers expose Set-Cookie via getSetCookie() (newer API) or headers.get()
    const raw = (typeof r.headers.getSetCookie === 'function')
      ? r.headers.getSetCookie()
      : (r.headers.get('set-cookie') || '').split(',').filter(Boolean);

    const cookies = raw.map(cookie => {
      const parts = cookie.split(';').map(p => p.trim());
      const flags  = parts.slice(1).map(f => f.toLowerCase());
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
      fetchTimeout(url, { headers: { 'User-Agent': UA } }),
      fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA } }),
    ]);
    const html    = htmlRes.status === 'fulfilled' ? await htmlRes.value.text() : '';
    const headers = headRes.status  === 'fulfilled' ? headRes.value.headers : new Headers();
    const tech = [];
    const h = (k) => headers.get(k);
    if (h('server'))        tech.push({ name: h('server'),        category: 'Web Server' });
    if (h('x-powered-by')) tech.push({ name: h('x-powered-by'),  category: 'Runtime' });
    if (h('cf-ray'))       tech.push({ name: 'Cloudflare',        category: 'CDN / Security' });
    if (h('x-varnish'))    tech.push({ name: 'Varnish Cache',     category: 'Cache' });
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

// ── Pages Function handler ────────────────────────────────────────────────────

export async function onRequestPost({ request }) {
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json',
  };

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON.' }, { status: 400, headers: corsHeaders }); }

  const { url, consent } = body;

  if (!consent)
    return Response.json({ error: 'You must confirm authorization to scan this website.' }, { status: 400, headers: corsHeaders });
  if (!url || typeof url !== 'string' || url.length > 500)
    return Response.json({ error: 'A valid URL is required.' }, { status: 400, headers: corsHeaders });

  const v = validateUrl(url.trim());
  if (!v.valid)
    return Response.json({ error: v.error }, { status: 400, headers: corsHeaders });

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

  const result = {
    url: v.url, hostname: v.hostname, timestamp: new Date().toISOString(),
    online: settle(online), headers: settle(headers), ssl: settle(ssl),
    dns: settle(dnsRec), whois: settle(whois), performance: settle(perf),
    wordpress: settle(wp), cookies: settle(cookies), techStack: settle(techStack),
  };

  return Response.json(result, { headers: corsHeaders });
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
  });
}
