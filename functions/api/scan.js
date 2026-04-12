/**
 * Cloudflare Pages Function — /api/scan
 * Workers runtime: fetch + DNS-over-HTTPS. No Node.js built-ins.
 */

const UA      = 'Mozilla/5.0 (compatible; UnicornScanner/2.0)';
const TIMEOUT = 18000;
const DOH     = 'https://dns.google/resolve';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fetchTimeout(url, opts = {}, ms = TIMEOUT) {
  const ctrl  = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(timer));
}

async function safeText(resp) {
  try { return await resp.text(); } catch { return ''; }
}

async function safeJson(resp) {
  try { return await resp.json(); } catch { return null; }
}

function pickRegex(html, ...patterns) {
  for (const re of patterns) { const m = html.match(re); if (m) return m[1]?.trim() || null; }
  return null;
}

// ── URL Validation ────────────────────────────────────────────────────────────

const PRIVATE = [
  /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^0\.0\.0\.0/, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i,
];

function validateUrl(raw) {
  let p;
  try { p = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`); }
  catch { return { valid: false, error: 'Invalid URL format.' }; }
  if (!['http:', 'https:'].includes(p.protocol)) return { valid: false, error: 'Only HTTP/HTTPS supported.' };
  if (PRIVATE.some(r => r.test(p.hostname))) return { valid: false, error: 'Scanning private addresses is not permitted.' };
  if (!/^[a-zA-Z0-9.\-]+$/.test(p.hostname)) return { valid: false, error: 'Invalid hostname characters.' };
  return { valid: true, hostname: p.hostname, url: p.href };
}

// ── DoH lookup helper ─────────────────────────────────────────────────────────

async function dohLookup(name, type) {
  try {
    const r = await fetchTimeout(`${DOH}?name=${encodeURIComponent(name)}&type=${type}`,
      { headers: { Accept: 'application/dns-json' } }, 8000);
    const d = await safeJson(r);
    return d?.Answer || [];
  } catch { return []; }
}

// ── 1. Online check ───────────────────────────────────────────────────────────

async function checkOnline(url) {
  const start = Date.now();
  try {
    const r = await fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA }, redirect: 'follow' });
    return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
  } catch {
    try {
      const r = await fetchTimeout(url, { headers: { 'User-Agent': UA }, redirect: 'follow' });
      return { status: r.status, statusText: r.statusText, responseTime: Date.now() - start };
    } catch (e) { return { error: e.message }; }
  }
}

// ── 2. HTTP Headers + security score ─────────────────────────────────────────

async function getHeaders(url) {
  try {
    const r = await fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA }, redirect: 'follow' });
    const SEC = ['strict-transport-security','content-security-policy','x-frame-options',
      'x-content-type-options','referrer-policy','permissions-policy'];
    const WANT = ['server','x-powered-by','content-type','via','cf-ray','x-varnish',
      'x-cache','age','cache-control','x-generator','x-pingback','link',...SEC];
    const headers = {};
    for (const k of WANT) { const v = r.headers.get(k); if (v) headers[k] = v; }
    const present = SEC.filter(k => !!r.headers.get(k));
    return { headers, securityHeaders: Object.fromEntries(SEC.map(k => [k, !!r.headers.get(k)])),
      securityScore: `${present.length}/${SEC.length}` };
  } catch (e) { return { error: e.message }; }
}

// ── 3. SSL (Workers: infer from HTTPS reachability) ──────────────────────────

async function getSSL(hostname) {
  try {
    const r = await fetchTimeout(`https://${hostname}`, { method: 'HEAD', headers: { 'User-Agent': UA } });
    // Extract cert info from CF headers if available
    const certExpiry = r.headers.get('cf-cert-verified') || null;
    return { httpsReachable: r.ok || r.status < 500, status: r.status,
      note: 'Full cert details need server-side TLS inspection.', certExpiry };
  } catch (e) { return { httpsReachable: false, error: e.message }; }
}

// ── 4. DNS Records ────────────────────────────────────────────────────────────

async function getDNS(hostname) {
  const result = {};
  const answers = await Promise.allSettled([
    dohLookup(hostname, 'A').then(a => { result.A = a.filter(r=>r.type===1).map(r=>r.data); }),
    dohLookup(hostname, 'AAAA').then(a => { result.AAAA = a.filter(r=>r.type===28).map(r=>r.data); }),
    dohLookup(hostname, 'MX').then(a => {
      result.MX = a.filter(r=>r.type===15).map(r => {
        const [pri,...parts] = r.data.split(' '); return { priority: Number(pri), exchange: parts.join(' ') };
      });
    }),
    dohLookup(hostname, 'NS').then(a => { result.NS = a.filter(r=>r.type===2).map(r=>r.data); }),
    dohLookup(hostname, 'TXT').then(a => { result.TXT = a.filter(r=>r.type===16).map(r=>r.data.replace(/"/g,'')); }),
    dohLookup(hostname, 'CAA').then(a => { result.CAA = a.filter(r=>r.type===257).map(r=>r.data); }),
    dohLookup(hostname, 'SOA').then(a => { const s=a.find(r=>r.type===6); if(s) result.SOA=s.data; }),
  ]);
  return result;
}

// ── 5. DNS Propagation (whatmydns-like) ──────────────────────────────────────

async function getDNSPropagation(hostname) {
  const resolvers = [
    { name: 'Google (8.8.8.8)',       url: 'https://dns.google/resolve' },
    { name: 'Cloudflare (1.1.1.1)',   url: 'https://cloudflare-dns.com/dns-query' },
    { name: 'Quad9 (9.9.9.9)',        url: 'https://dns.quad9.net:5053/dns-query' },
    { name: 'OpenDNS',                url: 'https://doh.opendns.com/dns-query' },
    { name: 'AdGuard',                url: 'https://dns.adguard.com/dns-query' },
    { name: 'NextDNS',                url: 'https://dns.nextdns.io/dns-query' },
    { name: 'Comcast',                url: 'https://doh.xfinity.com/dns-query' },
  ];
  const results = {};
  await Promise.allSettled(resolvers.map(async ({ name, url }) => {
    try {
      const r = await fetchTimeout(
        `${url}?name=${encodeURIComponent(hostname)}&type=A`,
        { headers: { Accept: 'application/dns-json' } }, 8000);
      const d = await safeJson(r);
      results[name] = (d?.Answer || []).filter(a => a.type === 1).map(a => a.data);
    } catch { results[name] = null; }
  }));
  return results;
}

// ── 6. Email security (SPF, DMARC, DKIM) ─────────────────────────────────────

async function getEmailSecurity(hostname) {
  const domain = hostname.replace(/^www\./, '');
  const dkimSelectors = ['google','selector1','selector2','k1','default','mail','dkim'];

  const [spfAnswers, dmarcAnswers, ...dkimAnswers] = await Promise.all([
    dohLookup(domain, 'TXT'),
    dohLookup(`_dmarc.${domain}`, 'TXT'),
    ...dkimSelectors.map(sel => dohLookup(`${sel}._domainkey.${domain}`, 'TXT')),
  ]);

  const txts  = spfAnswers.filter(r=>r.type===16).map(r=>r.data.replace(/"/g,''));
  const spf   = txts.find(t => t.startsWith('v=spf1')) || null;
  const dmarc = dmarcAnswers.filter(r=>r.type===16).map(r=>r.data.replace(/"/g,'')).find(t=>t.startsWith('v=DMARC1')) || null;

  const dkimFound = dkimSelectors
    .map((sel, i) => ({ selector: sel, found: dkimAnswers[i].length > 0 }))
    .filter(d => d.found);

  return {
    spf, hasSPF: !!spf,
    dmarc, hasDMARC: !!dmarc,
    dkim: dkimFound, hasDKIM: dkimFound.length > 0,
    mxExists: (await dohLookup(domain, 'MX')).length > 0,
  };
}

// ── 7. WHOIS via RDAP ─────────────────────────────────────────────────────────

async function getWhois(hostname) {
  const domain = hostname.replace(/^www\./, '');
  try {
    const r = await fetchTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`,
      { headers: { Accept: 'application/json' } });
    if (!r.ok) return { error: `RDAP returned ${r.status}` };
    const d = await safeJson(r);
    if (!d) return { error: 'Invalid RDAP response' };

    const getEvent = action => d.events?.find(e => e.eventAction === action)?.eventDate ?? null;
    const getEntity = role => d.entities?.find(e => e.roles?.includes(role));
    const vcard = (entity, field) => entity?.vcardArray?.[1]?.find(f => f[0] === field)?.[3] ?? null;

    const registrar  = getEntity('registrar');
    const registrant = getEntity('registrant');
    const admin      = getEntity('administrative');
    const tech       = getEntity('technical');

    return {
      registrar:         vcard(registrar, 'fn'),
      registrarUrl:      registrar?.links?.find(l=>l.rel==='self')?.href || null,
      registrarEmail:    vcard(registrar, 'email'),
      createdDate:       getEvent('registration'),
      expiryDate:        getEvent('expiration'),
      updatedDate:       getEvent('last changed'),
      registrantName:    vcard(registrant, 'fn'),
      registrantOrg:     vcard(registrant, 'org'),
      registrantEmail:   vcard(registrant, 'email'),
      registrantAddress: vcard(registrant, 'adr'),
      registrantCountry: registrant?.vcardArray?.[1]?.find(f=>f[0]==='adr')?.[1]?.['country-name'] ?? null,
      adminEmail:        vcard(admin, 'email'),
      techEmail:         vcard(tech, 'email'),
      nameServers:       (d.nameservers||[]).map(ns=>ns.ldhName?.toLowerCase()).filter(Boolean).slice(0,8),
      status:            (d.status||[]).slice(0,6),
      dnssec:            d.secureDNS?.delegationSigned ? 'Signed' : 'Unsigned',
      port43:            d.port43 || null,
    };
  } catch (e) { return { error: e.message }; }
}

// ── 8. Performance ────────────────────────────────────────────────────────────

async function getPerformance(url) {
  const start = Date.now();
  try {
    const r = await fetchTimeout(url, { headers: { 'User-Agent': UA }, redirect: 'follow' }, 30000);
    const text = await safeText(r);
    const totalTime = Date.now() - start;
    const size = new TextEncoder().encode(text).length;
    return { totalTime, httpCode: r.status, size, sizeKB: (size/1024).toFixed(1),
      transferRate: size > 0 ? ((size/1024)/(totalTime/1000)).toFixed(1) : null };
  } catch (e) { return { error: e.message }; }
}

// ── 9. Meta / SEO tags ────────────────────────────────────────────────────────

async function getMeta(url, cachedHtml) {
  try {
    const html = cachedHtml || await fetchTimeout(url, { headers: { 'User-Agent': UA }, redirect: 'follow' }).then(safeText);
    const pm = (re) => pickRegex(html, re);
    // Handle both content="..." and content='...' attribute order variations
    const meta = (name) =>
      pm(new RegExp(`<meta[^>]*name=["']${name}["'][^>]*content=["']([^"']+)`, 'i')) ||
      pm(new RegExp(`<meta[^>]*content=["']([^"']+)["'][^>]*name=["']${name}["']`, 'i'));
    const og = (prop) =>
      pm(new RegExp(`<meta[^>]*property=["']og:${prop}["'][^>]*content=["']([^"']+)`, 'i')) ||
      pm(new RegExp(`<meta[^>]*content=["']([^"']+)["'][^>]*property=["']og:${prop}["']`, 'i'));
    const tw = (name) =>
      pm(new RegExp(`<meta[^>]*name=["']twitter:${name}["'][^>]*content=["']([^"']+)`, 'i'));

    return {
      title:           pm(/<title[^>]*>([^<]{1,200})<\/title>/i),
      description:     meta('description'),
      keywords:        meta('keywords'),
      robots:          meta('robots'),
      viewport:        meta('viewport'),
      charset:         pm(/charset=["']?([^"'\s;>]+)/i),
      canonical:       pm(/<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)/i),
      generator:       meta('generator'),
      ogTitle:         og('title'),
      ogDescription:   og('description'),
      ogImage:         og('image'),
      ogType:          og('type'),
      ogSiteName:      og('site_name'),
      ogUrl:           og('url'),
      twitterCard:     tw('card'),
      twitterSite:     tw('site'),
      twitterTitle:    tw('title'),
      hasSchema:       html.includes('application/ld+json'),
      hasFavicon:      html.includes('rel="icon"') || html.includes("rel='icon'") || html.includes('rel="shortcut icon"'),
    };
  } catch (e) { return { error: e.message }; }
}

// ── 10. Common files ──────────────────────────────────────────────────────────

async function getCommonFiles(url) {
  const base = url.replace(/\/$/, '');
  const checks = [
    { key: 'robots',   path: '/robots.txt' },
    { key: 'sitemap',  path: '/sitemap.xml' },
    { key: 'sitemap2', path: '/sitemap_index.xml' },
    { key: 'security', path: '/.well-known/security.txt' },
    { key: 'ads',      path: '/ads.txt' },
    { key: 'humans',   path: '/humans.txt' },
    { key: 'manifest', path: '/manifest.json' },
  ];
  const results = {};
  await Promise.allSettled(checks.map(async ({ key, path }) => {
    try {
      const r = await fetchTimeout(`${base}${path}`, { headers: { 'User-Agent': UA } }, 8000);
      if (r.status === 200) {
        const text = await safeText(r);
        results[key] = { found: true, size: text.length,
          preview: text.slice(0, 600).trim(),
          urlCount: key.includes('sitemap') ? (text.match(/<loc>/g)||[]).length : undefined };
      } else { results[key] = { found: false, status: r.status }; }
    } catch { results[key] = { found: false }; }
  }));
  // Merge sitemap results
  if (!results.sitemap?.found && results.sitemap2?.found) results.sitemap = results.sitemap2;
  delete results.sitemap2;
  return results;
}

// ── 11. IP Geolocation ────────────────────────────────────────────────────────

async function getIPInfo(hostname) {
  try {
    const aRecords = await dohLookup(hostname, 'A');
    const ip = aRecords.find(r => r.type === 1)?.data;
    if (!ip) return { error: 'No A record found' };
    const r = await fetchTimeout(`https://ipapi.co/${ip}/json/`,
      { headers: { 'User-Agent': UA } }, 8000);
    const d = await safeJson(r);
    if (!d || d.error) return { ip, error: d?.reason || 'Lookup failed' };
    return {
      ip, city: d.city, region: d.region, country: d.country_name,
      countryCode: d.country_code, continent: d.continent_code,
      latitude: d.latitude, longitude: d.longitude,
      org: d.org, asn: d.asn, isp: d.org,
      timezone: d.timezone, currency: d.currency,
    };
  } catch (e) { return { error: e.message }; }
}

// ── 12. Social links & emails ─────────────────────────────────────────────────

async function getSocialsAndEmails(url, cachedHtml) {
  try {
    const html = cachedHtml || await fetchTimeout(url, { headers: { 'User-Agent': UA }, redirect: 'follow' }).then(safeText);
    const emails = [...new Set((html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[])
      .filter(e => !e.includes('.png') && !e.includes('.jpg') && !e.includes('.svg')))]
      .slice(0, 15);

    const social = (pattern) => {
      const m = html.match(pattern); return m ? m[0] : null;
    };
    const extract = (re) => { const m = html.match(re); return m ? `https://${m[0]}` : null; };

    return {
      emails,
      socials: {
        facebook:  extract(/facebook\.com\/(?!sharer|share|dialog)[a-zA-Z0-9._\-]+/),
        twitter:   extract(/(?:twitter|x)\.com\/(?!intent|share)[a-zA-Z0-9_]+/),
        instagram: extract(/instagram\.com\/[a-zA-Z0-9._]+/),
        linkedin:  extract(/linkedin\.com\/(?:company|in)\/[a-zA-Z0-9_\-]+/),
        youtube:   extract(/youtube\.com\/(?:channel|user|c|@)[a-zA-Z0-9_\-]+/),
        github:    extract(/github\.com\/[a-zA-Z0-9_\-]+/),
        tiktok:    extract(/tiktok\.com\/@[a-zA-Z0-9._]+/),
        pinterest: extract(/pinterest\.com\/[a-zA-Z0-9_]+/),
      },
    };
  } catch (e) { return { error: e.message }; }
}

// ── 13. Security file checks ──────────────────────────────────────────────────

async function getSecurityChecks(url) {
  const base = url.replace(/\/$/, '');
  const checks = [
    { key: 'gitExposed',    path: '/.git/HEAD',      indicator: 'ref:' },
    { key: 'envExposed',    path: '/.env',            indicator: 'APP_' },
    { key: 'phpinfo',       path: '/phpinfo.php',     indicator: 'PHP Version' },
    { key: 'wpLogin',       path: '/wp-login.php',    indicator: 'wordpress' },
    { key: 'xmlrpc',        path: '/xmlrpc.php',      indicator: 'XML-RPC' },
    { key: 'adminExposed',  path: '/admin',           indicator: null },
    { key: 'configExposed', path: '/config.php',      indicator: null },
    { key: 'backupExposed', path: '/backup.zip',      indicator: null },
    { key: 'readmeHtml',    path: '/readme.html',     indicator: 'WordPress' },
    { key: 'licenseHtml',   path: '/license.txt',     indicator: 'WordPress' },
  ];
  const results = {};
  await Promise.allSettled(checks.map(async ({ key, path, indicator }) => {
    try {
      const r = await fetchTimeout(`${base}${path}`, { headers: { 'User-Agent': UA } }, 6000);
      if (r.status === 200) {
        const text = await safeText(r);
        results[key] = indicator ? text.includes(indicator) : true;
      } else { results[key] = false; }
    } catch { results[key] = false; }
  }));
  return results;
}

// ── 14. WordPress deep scan ───────────────────────────────────────────────────

async function detectWordPress(url) {
  try {
    const base = url.replace(/\/$/, '');
    const [htmlRes, versionRes] = await Promise.allSettled([
      fetchTimeout(url, { headers: { 'User-Agent': UA } }),
      fetchTimeout(`${base}/wp-includes/version.php`, { headers: { 'User-Agent': UA } }),
    ]);
    const html   = htmlRes.status === 'fulfilled' ? await safeText(htmlRes.value) : '';
    const wpHit  = versionRes.status === 'fulfilled' && versionRes.value.status === 200;
    const isWP   = html.includes('wp-content') || html.includes('wp-includes') || wpHit;
    if (!isWP) return { detected: false };

    // Core version
    const verMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9.]+)/i);
    let version = verMatch ? verMatch[1] : null;

    // Plugin slugs from HTML
    const pluginSlugs = [...new Set([...html.matchAll(/wp-content\/plugins\/([a-z0-9\-_]+)/gi)].map(m => m[1]))].slice(0, 20);

    // Theme slug from HTML
    const themeMatch = html.match(/wp-content\/themes\/([a-z0-9\-_]+)/i);
    const themeSlug = themeMatch ? themeMatch[1] : null;

    // Run detail fetches in parallel
    const [themeRes, usersRes, readmeRes, xmlrpcRes, ...pluginResponses] = await Promise.allSettled([
      themeSlug ? fetchTimeout(`${base}/wp-content/themes/${themeSlug}/style.css`, { headers: { 'User-Agent': UA } }) : Promise.resolve(null),
      fetchTimeout(`${base}/wp-json/wp/v2/users?per_page=10`, { headers: { 'User-Agent': UA } }),
      fetchTimeout(`${base}/readme.html`, { headers: { 'User-Agent': UA } }),
      fetchTimeout(`${base}/xmlrpc.php`, { method: 'POST', headers: { 'User-Agent': UA, 'Content-Type': 'text/xml' },
        body: '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>' }),
      // WordPress.org API for each plugin
      ...pluginSlugs.map(slug =>
        fetchTimeout(`https://api.wordpress.org/plugins/info/1.0/${slug}.json`, { headers: { 'User-Agent': UA } }, 8000)
      ),
    ]);

    // Parse theme style.css
    let theme = { slug: themeSlug };
    if (themeRes.status === 'fulfilled' && themeRes.value?.status === 200) {
      const css = await safeText(themeRes.value);
      theme = {
        slug:       themeSlug,
        name:       pickRegex(css, /Theme Name:\s*(.+)/i),
        version:    pickRegex(css, /Version:\s*(.+)/i),
        author:     pickRegex(css, /Author:\s*(?!URI)(.+)/i),
        authorUri:  pickRegex(css, /Author URI:\s*(.+)/i),
        themeUri:   pickRegex(css, /Theme URI:\s*(.+)/i),
        description:pickRegex(css, /Description:\s*(.+)/i),
        license:    pickRegex(css, /License:\s*(.+)/i),
      };
    }

    // Parse users
    let users = null;
    if (usersRes.status === 'fulfilled' && usersRes.value?.status === 200) {
      const d = await safeJson(usersRes.value);
      if (Array.isArray(d)) users = d.map(u => ({ id: u.id, name: u.name, slug: u.slug, url: u.url, description: u.description }));
    }
    const restApiEnabled = usersRes.status === 'fulfilled' && usersRes.value?.status !== 404;

    // Check version from readme.html if not found in meta
    if (!version && readmeRes.status === 'fulfilled' && readmeRes.value?.status === 200) {
      const txt = await safeText(readmeRes.value);
      const m = txt.match(/Version\s+([0-9.]+)/i);
      if (m) version = m[1];
    }
    const readmeExposed = readmeRes.status === 'fulfilled' && readmeRes.value?.status === 200;

    // xmlrpc enabled?
    const xmlrpcEnabled = xmlrpcRes.status === 'fulfilled' && xmlrpcRes.value?.status === 200;

    // Parse plugin details from WordPress.org API
    const plugins = await Promise.all(pluginSlugs.map(async (slug, i) => {
      const res = pluginResponses[i];
      if (res.status === 'fulfilled' && res.value?.ok) {
        const d = await safeJson(res.value);
        if (d && !d.error) return { slug, name: d.name, version: d.version, author: d.author?.replace(/<[^>]+>/g,''), rating: d.rating, activeInstalls: d.active_installs };
      }
      return { slug };
    }));

    return { detected: true, version, theme, plugins, users, restApiEnabled, xmlrpcEnabled, readmeExposed };
  } catch (e) { return { error: e.message }; }
}

// ── 15. Tech stack ────────────────────────────────────────────────────────────

async function getTechStack(url, cachedHtml) {
  try {
    const [htmlFetch, headFetch] = await Promise.allSettled([
      cachedHtml ? Promise.resolve(cachedHtml) : fetchTimeout(url, { headers: { 'User-Agent': UA } }).then(safeText),
      fetchTimeout(url, { method: 'HEAD', headers: { 'User-Agent': UA } }),
    ]);
    const html    = htmlFetch.status === 'fulfilled' ? htmlFetch.value : '';
    const headers = headFetch.status === 'fulfilled' ? headFetch.value.headers : new Headers();
    const h = k  => headers.get(k);
    const tech = [];
    if (h('server'))         tech.push({ name: h('server'),        category: 'Web Server' });
    if (h('x-powered-by'))  tech.push({ name: h('x-powered-by'),  category: 'Runtime' });
    if (h('cf-ray'))         tech.push({ name: 'Cloudflare',       category: 'CDN / Security' });
    if (h('x-varnish'))      tech.push({ name: 'Varnish Cache',    category: 'Cache' });
    if (h('x-drupal-cache')) tech.push({ name: 'Drupal',           category: 'CMS' });
    const patterns = [
      [/_next\//i,                    'Next.js',           'JS Framework'],
      [/react(?:\.js|dom)/i,          'React',             'JS Framework'],
      [/vue(?:\.js|\.min\.js)/i,      'Vue.js',            'JS Framework'],
      [/angular(?:\.js|\/)/i,         'Angular',           'JS Framework'],
      [/nuxt(?:\.js)?/i,              'Nuxt.js',           'JS Framework'],
      [/svelte/i,                     'Svelte',            'JS Framework'],
      [/remix(?:\.js)?/i,             'Remix',             'JS Framework'],
      [/astro/i,                      'Astro',             'JS Framework'],
      [/jquery(?:\.min)?\.js/i,       'jQuery',            'JS Library'],
      [/bootstrap(?:\.min)?\.css/i,   'Bootstrap',         'CSS Framework'],
      [/tailwind/i,                   'Tailwind CSS',      'CSS Framework'],
      [/wp-content/i,                 'WordPress',         'CMS'],
      [/drupal\.js/i,                 'Drupal',            'CMS'],
      [/joomla/i,                     'Joomla',            'CMS'],
      [/shopify/i,                    'Shopify',           'E-commerce'],
      [/woocommerce/i,                'WooCommerce',       'E-commerce'],
      [/squarespace/i,                'Squarespace',       'Website Builder'],
      [/webflow/i,                    'Webflow',           'Website Builder'],
      [/wix\.com/i,                   'Wix',               'Website Builder'],
      [/gatsby/i,                     'Gatsby',            'Static Site'],
      [/hubspot/i,                    'HubSpot',           'Marketing'],
      [/gtag\(|google-analytics|GA4/i,'Google Analytics',  'Analytics'],
      [/matomo|piwik/i,               'Matomo',            'Analytics'],
      [/plausible/i,                  'Plausible',         'Analytics'],
      [/hotjar/i,                     'Hotjar',            'Analytics'],
      [/intercom/i,                   'Intercom',          'Support'],
      [/zendesk/i,                    'Zendesk',           'Support'],
      [/stripe\.js/i,                 'Stripe',            'Payments'],
      [/paypal/i,                     'PayPal',            'Payments'],
      [/recaptcha/i,                  'reCAPTCHA',         'Security'],
      [/cloudflare/i,                 'Cloudflare',        'CDN / Security'],
      [/fastly/i,                     'Fastly',            'CDN'],
      [/akamai/i,                     'Akamai',            'CDN'],
      [/amazonaws\.com/i,             'Amazon AWS',        'Hosting'],
      [/googletagmanager/i,           'Google Tag Manager','Analytics'],
      [/facebook\.net\/en_US\/fbevents/i, 'Meta Pixel',   'Analytics'],
    ];
    for (const [re, name, cat] of patterns) if (re.test(html)) tech.push({ name, category: cat });
    return { technologies: [...new Map(tech.map(t=>[t.name,t])).values()] };
  } catch (e) { return { error: e.message }; }
}

// ── 16. Cookies ───────────────────────────────────────────────────────────────

async function getCookies(url) {
  try {
    const r = await fetchTimeout(url, { method: 'GET', headers: { 'User-Agent': UA }, redirect: 'follow' });
    const raw = typeof r.headers.getSetCookie === 'function'
      ? r.headers.getSetCookie()
      : (r.headers.get('set-cookie') || '').split(/,(?=[^;]+=[^;]*)/).filter(Boolean);
    const cookies = raw.map(c => {
      const parts = c.split(';').map(p => p.trim());
      const flags  = parts.slice(1).map(f => f.toLowerCase());
      return { name: parts[0].split('=')[0],
        httpOnly: flags.includes('httponly'),
        secure:   flags.includes('secure'),
        sameSite: flags.find(f=>f.startsWith('samesite='))?.split('=')[1]||null,
        path:     flags.find(f=>f.startsWith('path='))?.split('=')[1]||null };
    });
    return { cookies, count: cookies.length };
  } catch (e) { return { error: e.message }; }
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

export async function onRequestPost({ request }) {
  const CORS = { 'Access-Control-Allow-Origin': '*', 'Content-Type': 'application/json' };

  let body;
  try { body = await request.json(); }
  catch { return Response.json({ error: 'Invalid JSON.' }, { status: 400, headers: CORS }); }

  const { url, consent } = body;
  if (!consent) return Response.json({ error: 'You must confirm authorization to scan this website.' }, { status: 400, headers: CORS });
  if (!url || typeof url !== 'string' || url.length > 500) return Response.json({ error: 'A valid URL is required.' }, { status: 400, headers: CORS });

  const v = validateUrl(url.trim());
  if (!v.valid) return Response.json({ error: v.error }, { status: 400, headers: CORS });

  const settle = r => r.status === 'fulfilled' ? r.value : { error: r.reason?.message || 'Failed' };

  const [online, headers, ssl, dns, dnsProp, emailSec, whois, perf, meta, commonFiles, ipInfo, socials, security, wordpress, techStack, cookies] =
    await Promise.allSettled([
      checkOnline(v.url),
      getHeaders(v.url),
      getSSL(v.hostname),
      getDNS(v.hostname),
      getDNSPropagation(v.hostname),
      getEmailSecurity(v.hostname),
      getWhois(v.hostname),
      getPerformance(v.url),
      getMeta(v.url),
      getCommonFiles(v.url),
      getIPInfo(v.hostname),
      getSocialsAndEmails(v.url),
      getSecurityChecks(v.url),
      detectWordPress(v.url),
      getTechStack(v.url),
      getCookies(v.url),
    ]);

  return Response.json({
    url: v.url, hostname: v.hostname, timestamp: new Date().toISOString(),
    online:      settle(online),
    headers:     settle(headers),
    ssl:         settle(ssl),
    dns:         settle(dns),
    dnsPropagation: settle(dnsProp),
    emailSecurity:  settle(emailSec),
    whois:       settle(whois),
    performance: settle(perf),
    meta:        settle(meta),
    commonFiles: settle(commonFiles),
    ipInfo:      settle(ipInfo),
    socials:     settle(socials),
    security:    settle(security),
    wordpress:   settle(wordpress),
    techStack:   settle(techStack),
    cookies:     settle(cookies),
  }, { headers: CORS });
}

export async function onRequestOptions() {
  return new Response(null, { status: 204, headers: {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  }});
}
