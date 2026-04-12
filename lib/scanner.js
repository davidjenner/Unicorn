'use strict';

/**
 * Unicorn Scanner — Node.js shared scan logic (Express / Netlify Lambda).
 * No shell exec. WHOIS via TCP. All other checks via axios / Node built-ins.
 */

const axios  = require('axios');
const dns    = require('dns').promises;
const tls    = require('tls');
const net    = require('net');
const { URL } = require('url');

// ── Config ────────────────────────────────────────────────────────────────────

const UA      = 'Mozilla/5.0 (compatible; UnicornScanner/2.0)';
const TIMEOUT = 18000;

const axiosHead = (url) =>
  axios.head(url, { timeout: TIMEOUT, headers: { 'User-Agent': UA }, maxRedirects: 5, validateStatus: () => true });

const axiosGet = (url, maxBytes = 2 * 1024 * 1024) =>
  axios.get(url, { timeout: TIMEOUT, headers: { 'User-Agent': UA }, maxRedirects: 5,
    maxContentLength: maxBytes, validateStatus: () => true, responseType: 'text' });

// ── URL validation ─────────────────────────────────────────────────────────────

const PRIVATE = [
  /^localhost$/i, /^127\./, /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^0\.0\.0\.0/, /^169\.254\./, /^::1$/, /^fc00:/i, /^fe80:/i,
];

function validateUrl(raw) {
  let p;
  try { p = new URL(/^https?:\/\//i.test(raw) ? raw : `https://${raw}`); }
  catch { return { valid: false, error: 'Invalid URL format.' }; }
  if (!['http:','https:'].includes(p.protocol)) return { valid: false, error: 'Only HTTP/HTTPS supported.' };
  if (PRIVATE.some(r => r.test(p.hostname))) return { valid: false, error: 'Scanning private addresses is not permitted.' };
  if (!/^[a-zA-Z0-9.\-]+$/.test(p.hostname)) return { valid: false, error: 'Invalid hostname characters.' };
  return { valid: true, hostname: p.hostname, url: p.href };
}

function pick(html, ...patterns) {
  for (const re of patterns) { const m = html.match(re); if (m) return m[1]?.trim() || null; }
  return null;
}

// ── WHOIS via TCP ─────────────────────────────────────────────────────────────

const WHOIS_SERVERS = {
  com:'whois.verisign-grs.com', net:'whois.verisign-grs.com', org:'whois.pir.org',
  io:'whois.nic.io', co:'whois.nic.co', uk:'whois.nic.uk', 'co.uk':'whois.nic.uk',
  de:'whois.denic.de', fr:'whois.nic.fr', nl:'whois.domain-registry.nl',
  au:'whois.auda.org.au', ca:'whois.cira.ca', eu:'whois.eu',
  info:'whois.afilias.net', biz:'whois.biz', us:'whois.nic.us',
  dev:'whois.nic.google', app:'whois.nic.google', ai:'whois.nic.ai',
  me:'whois.nic.me', tv:'tvwhois.verisign-grs.com',
};

function whoisTcp(domain) {
  const parts  = domain.split('.');
  const tld2   = parts.slice(-2).join('.').toLowerCase();
  const tld1   = parts[parts.length - 1].toLowerCase();
  const server = WHOIS_SERVERS[tld2] || WHOIS_SERVERS[tld1] || `whois.nic.${tld1}`;
  return new Promise(resolve => {
    const socket = net.createConnection({ host: server, port: 43 });
    let data = '';
    socket.setTimeout(12000);
    socket.on('connect', () => socket.write(`${domain}\r\n`));
    socket.on('data',    c  => { data += c; });
    socket.on('end',     ()  => resolve(data));
    socket.on('error',   err => resolve(`Error: ${err.message}`));
    socket.on('timeout', () => { socket.destroy(); resolve('Error: timeout'); });
  });
}

// ── 1. Online ─────────────────────────────────────────────────────────────────

async function checkOnline(url) {
  const t = Date.now();
  try {
    const r = await axiosHead(url);
    return { status: r.status, statusText: r.statusText, responseTime: Date.now()-t };
  } catch {
    try { const r = await axiosGet(url,512*1024); return { status:r.status, statusText:r.statusText, responseTime:Date.now()-t }; }
    catch (e) { return { error: e.message }; }
  }
}

// ── 2. Headers ────────────────────────────────────────────────────────────────

async function getHeaders(url) {
  try {
    const r = await axiosHead(url);
    const h = r.headers;
    const SEC  = ['strict-transport-security','content-security-policy','x-frame-options','x-content-type-options','referrer-policy','permissions-policy'];
    const WANT = ['server','x-powered-by','content-type','via','cf-ray','x-varnish','x-cache','age','cache-control','x-generator','x-pingback','link',...SEC];
    const headers = {};
    for (const k of WANT) if (h[k]) headers[k] = h[k];
    const present = SEC.filter(k => !!h[k]);
    return { headers, securityHeaders: Object.fromEntries(SEC.map(k=>[k,!!h[k]])), securityScore: `${present.length}/${SEC.length}` };
  } catch (e) { return { error: e.message }; }
}

// ── 3. SSL ────────────────────────────────────────────────────────────────────

async function getSSL(hostname) {
  return new Promise(resolve => {
    const socket = tls.connect({ host:hostname, port:443, servername:hostname, rejectUnauthorized:false, timeout:10000 }, () => {
      const cert  = socket.getPeerCertificate(true);
      const proto = socket.getProtocol?.() || 'unknown';
      socket.destroy();
      if (!cert?.subject) { resolve({ error: 'No certificate found' }); return; }
      const daysRemaining = Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000);
      resolve({ subject:cert.subject, issuer:cert.issuer, validFrom:cert.valid_from, validTo:cert.valid_to,
        daysRemaining, fingerprint:cert.fingerprint, protocol:proto, expired:daysRemaining<0,
        sans: cert.subjectaltname?.split(', ').map(s=>s.replace('DNS:','')) || [] });
    });
    socket.on('error', e => resolve({ error: e.message }));
    socket.setTimeout(10000, () => { socket.destroy(); resolve({ error: 'Timed out' }); });
  });
}

// ── 4. DNS records ────────────────────────────────────────────────────────────

async function getDNS(hostname) {
  const r = {};
  await Promise.allSettled([
    dns.resolve4(hostname).then(v => { r.A    = v; }).catch(()=>{}),
    dns.resolve6(hostname).then(v => { r.AAAA = v; }).catch(()=>{}),
    dns.resolveMx(hostname).then(v => { r.MX  = v; }).catch(()=>{}),
    dns.resolveNs(hostname).then(v => { r.NS  = v; }).catch(()=>{}),
    dns.resolveTxt(hostname).then(v => { r.TXT = v.map(a=>a.join('')); }).catch(()=>{}),
    dns.resolveCaa(hostname).then(v => { r.CAA = v; }).catch(()=>{}),
    dns.resolveSoa(hostname).then(v => { r.SOA = v; }).catch(()=>{}),
  ]);
  return r;
}

// ── 5. DNS Propagation ────────────────────────────────────────────────────────

async function getDNSPropagation(hostname) {
  const resolvers = [
    { name:'Google (8.8.8.8)',     url:'https://dns.google/resolve' },
    { name:'Cloudflare (1.1.1.1)', url:'https://cloudflare-dns.com/dns-query' },
    { name:'Quad9 (9.9.9.9)',      url:'https://dns.quad9.net:5053/dns-query' },
    { name:'OpenDNS',              url:'https://doh.opendns.com/dns-query' },
    { name:'AdGuard',              url:'https://dns.adguard.com/dns-query' },
    { name:'NextDNS',              url:'https://dns.nextdns.io/dns-query' },
  ];
  const results = {};
  await Promise.allSettled(resolvers.map(async ({ name, url }) => {
    try {
      const r = await axiosGet(`${url}?name=${encodeURIComponent(hostname)}&type=A`, 64*1024);
      const d = r.data ? JSON.parse(r.data) : null;
      results[name] = (d?.Answer||[]).filter(a=>a.type===1).map(a=>a.data);
    } catch { results[name] = null; }
  }));
  return results;
}

// ── 6. Email security ─────────────────────────────────────────────────────────

async function getEmailSecurity(hostname) {
  const domain = hostname.replace(/^www\./,'');
  const dkimSels = ['google','selector1','selector2','k1','default','mail','dkim'];
  const [spfTxt, dmarcTxt, ...dkimResults] = await Promise.allSettled([
    dns.resolveTxt(domain),
    dns.resolveTxt(`_dmarc.${domain}`),
    ...dkimSels.map(sel => dns.resolveTxt(`${sel}._domainkey.${domain}`)),
  ]);
  const spfRecs  = spfTxt.status==='fulfilled'  ? spfTxt.value.map(a=>a.join(''))  : [];
  const dmarcRecs= dmarcTxt.status==='fulfilled' ? dmarcTxt.value.map(a=>a.join('')): [];
  const spf   = spfRecs.find(t=>t.startsWith('v=spf1'))   || null;
  const dmarc = dmarcRecs.find(t=>t.startsWith('v=DMARC1'))|| null;
  const dkimFound = dkimSels.map((sel,i)=>({ selector:sel, found:dkimResults[i].status==='fulfilled' && dkimResults[i].value.length>0 })).filter(d=>d.found);
  let mxExists = false;
  try { const mx = await dns.resolveMx(domain); mxExists = mx.length > 0; } catch {}
  return { spf, hasSPF:!!spf, dmarc, hasDMARC:!!dmarc, dkim:dkimFound, hasDKIM:dkimFound.length>0, mxExists };
}

// ── 7. WHOIS ──────────────────────────────────────────────────────────────────

async function getWhois(hostname) {
  const domain = hostname.replace(/^www\./,'');
  const raw = await whoisTcp(domain);
  if (raw.startsWith('Error:')) return { error: raw };
  const p = re => { const m = raw.match(re); return m?m[1].trim():null; };
  return {
    registrar:         p(/^Registrar:\s*(.+)/im),
    registrarUrl:      p(/Registrar URL:\s*(.+)/i),
    registrarEmail:    p(/Registrar Abuse Contact Email:\s*(.+)/i),
    createdDate:       p(/Creation Date:\s*(.+)/i),
    expiryDate:        p(/Registry Expiry Date:\s*(.+)/i),
    updatedDate:       p(/Updated Date:\s*(.+)/i),
    registrantName:    p(/Registrant Name:\s*(.+)/i),
    registrantOrg:     p(/Registrant Organization:\s*(.+)/i),
    registrantEmail:   p(/Registrant Email:\s*(.+)/i),
    registrantCountry: p(/Registrant Country:\s*(.+)/i),
    adminEmail:        p(/Admin Email:\s*(.+)/i),
    techEmail:         p(/Tech Email:\s*(.+)/i),
    nameServers: [...new Set((raw.match(/Name Server:\s*(.+)/gi)||[]).map(s=>s.replace(/Name Server:\s*/i,'').trim().toLowerCase()))].slice(0,8),
    status:      (raw.match(/Domain Status:\s*(\S+)/gi)||[]).map(s=>s.replace(/Domain Status:\s*/i,'').trim()).slice(0,6),
    dnssec:            p(/DNSSEC:\s*(.+)/i),
  };
}

// ── 8. Performance ────────────────────────────────────────────────────────────

async function getPerformance(url) {
  const t = Date.now();
  try {
    const r = await axiosGet(url, 5*1024*1024);
    const ms = Date.now()-t;
    const size = typeof r.data==='string' ? Buffer.byteLength(r.data) : 0;
    return { totalTime:ms, httpCode:r.status, size, sizeKB:(size/1024).toFixed(1),
      transferRate: size>0 ? ((size/1024)/(ms/1000)).toFixed(1) : null };
  } catch (e) { return { error: e.message }; }
}

// ── 9. Meta / SEO ─────────────────────────────────────────────────────────────

async function getMeta(url) {
  try {
    const r = await axiosGet(url);
    const html = r.data || '';
    const meta = (name) => pick(html,
      new RegExp(`<meta[^>]*name=["']${name}["'][^>]*content=["']([^"']+)`,'i'),
      new RegExp(`<meta[^>]*content=["']([^"']+)["'][^>]*name=["']${name}["']`,'i'));
    const og = (prop) => pick(html,
      new RegExp(`<meta[^>]*property=["']og:${prop}["'][^>]*content=["']([^"']+)`,'i'),
      new RegExp(`<meta[^>]*content=["']([^"']+)["'][^>]*property=["']og:${prop}["']`,'i'));
    const tw = (name) => pick(html, new RegExp(`<meta[^>]*name=["']twitter:${name}["'][^>]*content=["']([^"']+)`,'i'));
    return {
      title:        pick(html, /<title[^>]*>([^<]{1,200})<\/title>/i),
      description:  meta('description'), keywords: meta('keywords'),
      robots:       meta('robots'), viewport: meta('viewport'),
      charset:      pick(html, /charset=["']?([^"'\s;>]+)/i),
      canonical:    pick(html, /<link[^>]*rel=["']canonical["'][^>]*href=["']([^"']+)/i),
      generator:    meta('generator'),
      ogTitle:      og('title'), ogDescription: og('description'), ogImage: og('image'),
      ogType:       og('type'), ogSiteName: og('site_name'), ogUrl: og('url'),
      twitterCard:  tw('card'), twitterSite: tw('site'), twitterTitle: tw('title'),
      hasSchema:    html.includes('application/ld+json'),
      hasFavicon:   html.includes('rel="icon"') || html.includes("rel='icon'") || html.includes('rel="shortcut icon"'),
    };
  } catch (e) { return { error: e.message }; }
}

// ── 10. Common files ──────────────────────────────────────────────────────────

async function getCommonFiles(url) {
  const base = url.replace(/\/$/,'');
  const checks = [
    { key:'robots',   path:'/robots.txt' },
    { key:'sitemap',  path:'/sitemap.xml' },
    { key:'sitemap2', path:'/sitemap_index.xml' },
    { key:'security', path:'/.well-known/security.txt' },
    { key:'ads',      path:'/ads.txt' },
    { key:'humans',   path:'/humans.txt' },
    { key:'manifest', path:'/manifest.json' },
  ];
  const results = {};
  await Promise.allSettled(checks.map(async ({ key, path }) => {
    try {
      const r = await axios.get(`${base}${path}`, { timeout:8000, headers:{'User-Agent':UA}, validateStatus:()=>true, responseType:'text' });
      if (r.status===200) {
        const text = r.data||'';
        results[key] = { found:true, size:text.length, preview:text.slice(0,600).trim(),
          urlCount: key.includes('sitemap') ? (text.match(/<loc>/g)||[]).length : undefined };
      } else { results[key] = { found:false, status:r.status }; }
    } catch { results[key] = { found:false }; }
  }));
  if (!results.sitemap?.found && results.sitemap2?.found) results.sitemap = results.sitemap2;
  delete results.sitemap2;
  return results;
}

// ── 11. IP Geolocation ────────────────────────────────────────────────────────

async function getIPInfo(hostname) {
  try {
    const addrs = await dns.resolve4(hostname).catch(() => []);
    const ip = addrs[0];
    if (!ip) return { error: 'No A record found' };
    const r = await axios.get(`https://ipapi.co/${ip}/json/`, { timeout:8000, headers:{'User-Agent':UA}, validateStatus:()=>true });
    const d = r.data;
    if (!d || d.error) return { ip, error: d?.reason||'Lookup failed' };
    return { ip, city:d.city, region:d.region, country:d.country_name, countryCode:d.country_code,
      latitude:d.latitude, longitude:d.longitude, org:d.org, asn:d.asn, timezone:d.timezone };
  } catch (e) { return { error: e.message }; }
}

// ── 12. Socials & emails ──────────────────────────────────────────────────────

async function getSocialsAndEmails(url) {
  try {
    const r = await axiosGet(url);
    const html = r.data || '';
    const emails = [...new Set((html.match(/[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g)||[])
      .filter(e=>!e.includes('.png')&&!e.includes('.jpg')&&!e.includes('.svg')))].slice(0,15);
    const extract = re => { const m=html.match(re); return m?`https://${m[0]}`:null; };
    return { emails, socials: {
      facebook:  extract(/facebook\.com\/(?!sharer|share|dialog)[a-zA-Z0-9._\-]+/),
      twitter:   extract(/(?:twitter|x)\.com\/(?!intent|share)[a-zA-Z0-9_]+/),
      instagram: extract(/instagram\.com\/[a-zA-Z0-9._]+/),
      linkedin:  extract(/linkedin\.com\/(?:company|in)\/[a-zA-Z0-9_\-]+/),
      youtube:   extract(/youtube\.com\/(?:channel|user|c|@)[a-zA-Z0-9_\-]+/),
      github:    extract(/github\.com\/[a-zA-Z0-9_\-]+/),
      tiktok:    extract(/tiktok\.com\/@[a-zA-Z0-9._]+/),
      pinterest: extract(/pinterest\.com\/[a-zA-Z0-9_]+/),
    }};
  } catch (e) { return { error: e.message }; }
}

// ── 13. Security checks ───────────────────────────────────────────────────────

async function getSecurityChecks(url) {
  const base = url.replace(/\/$/,'');
  const checks = [
    { key:'gitExposed',    path:'/.git/HEAD',    indicator:'ref:' },
    { key:'envExposed',    path:'/.env',          indicator:'APP_' },
    { key:'phpinfo',       path:'/phpinfo.php',   indicator:'PHP Version' },
    { key:'wpLogin',       path:'/wp-login.php',  indicator:'wordpress' },
    { key:'xmlrpc',        path:'/xmlrpc.php',    indicator:'XML-RPC' },
    { key:'adminExposed',  path:'/admin',         indicator:null },
    { key:'readmeHtml',    path:'/readme.html',   indicator:'WordPress' },
    { key:'licenseExposed',path:'/license.txt',   indicator:'WordPress' },
    { key:'backupExposed', path:'/backup.zip',    indicator:null },
  ];
  const results = {};
  await Promise.allSettled(checks.map(async ({ key, path, indicator }) => {
    try {
      const r = await axios.get(`${base}${path}`, { timeout:6000, headers:{'User-Agent':UA}, validateStatus:()=>true, responseType:'text', maxContentLength:64*1024 });
      if (r.status===200) results[key] = indicator ? (r.data||'').includes(indicator) : true;
      else results[key] = false;
    } catch { results[key] = false; }
  }));
  return results;
}

// ── 14. WordPress deep scan ───────────────────────────────────────────────────

function compareVersions(a, b) {
  const pa = String(a).split('.').map(n => parseInt(n) || 0);
  const pb = String(b).split('.').map(n => parseInt(n) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

async function detectWordPress(url) {
  try {
    const base = url.replace(/\/$/,'');
    const [htmlRes, versionRes] = await Promise.allSettled([
      axiosGet(url), axiosGet(`${base}/wp-includes/version.php`, 64*1024),
    ]);
    const html  = htmlRes.status==='fulfilled' ? (htmlRes.value.data||'') : '';
    const wpHit = versionRes.status==='fulfilled' && versionRes.value.status===200;
    const isWP  = html.includes('wp-content')||html.includes('wp-includes')||wpHit;
    if (!isWP) return { detected:false };

    const verMatch   = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s+([0-9.]+)/i);
    let version      = verMatch ? verMatch[1] : null;
    const pluginSlugs= [...new Set([...html.matchAll(/wp-content\/plugins\/([a-z0-9\-_]+)/gi)].map(m=>m[1]))].slice(0,20);
    const themeMatch = html.match(/wp-content\/themes\/([a-z0-9\-_]+)/i);
    const themeSlug  = themeMatch ? themeMatch[1] : null;

    // All fetches in one batch. Plugins interleaved: [site_readme_0, wporg_0, site_readme_1, wporg_1 …]
    const [themeRes, usersRes, readmeRes, xmlrpcRes, ...allPluginRes] = await Promise.allSettled([
      themeSlug ? axiosGet(`${base}/wp-content/themes/${themeSlug}/style.css`, 64*1024) : Promise.resolve(null),
      axiosGet(`${base}/wp-json/wp/v2/users?per_page=10`, 64*1024),
      axiosGet(`${base}/readme.html`, 64*1024),
      axios.post(`${base}/xmlrpc.php`,
        '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName></methodCall>',
        { timeout:6000, headers:{'User-Agent':UA,'Content-Type':'text/xml'}, validateStatus:()=>true }),
      ...pluginSlugs.flatMap(slug => [
        axios.get(`${base}/wp-content/plugins/${slug}/readme.txt`,
          { timeout:8000, headers:{'User-Agent':UA}, validateStatus:()=>true, responseType:'text', maxContentLength:64*1024 }),
        axios.get(`https://api.wordpress.org/plugins/info/1.0/${slug}.json`,
          { timeout:8000, headers:{'User-Agent':UA}, validateStatus:()=>true }),
      ]),
    ]);

    let theme = { slug: themeSlug };
    if (themeRes.status==='fulfilled' && themeRes.value?.status===200) {
      const css = themeRes.value.data||'';
      theme = { slug:themeSlug,
        name:        pick(css, /Theme Name:\s*(.+)/i),
        version:     pick(css, /Version:\s*(.+)/i),
        author:      pick(css, /^Author:\s*(?!URI)(.+)/im),
        authorUri:   pick(css, /Author URI:\s*(.+)/i),
        themeUri:    pick(css, /Theme URI:\s*(.+)/i),
        description: pick(css, /Description:\s*(.+)/i),
        license:     pick(css, /License:\s*(.+)/i),
      };
    }

    let users = null;
    if (usersRes.status==='fulfilled' && usersRes.value?.status===200) {
      const d = usersRes.value.data;
      if (Array.isArray(d)) users = d.map(u=>({ id:u.id, name:u.name, slug:u.slug, url:u.url }));
    }
    const restApiEnabled = usersRes.status==='fulfilled' && usersRes.value?.status!==404;

    if (!version && readmeRes.status==='fulfilled' && readmeRes.value?.status===200) {
      const m = (readmeRes.value.data||'').match(/Version\s+([0-9.]+)/i);
      if (m) version = m[1];
    }
    const readmeExposed = readmeRes.status==='fulfilled' && readmeRes.value?.status===200;
    const xmlrpcEnabled = xmlrpcRes.status==='fulfilled' && xmlrpcRes.value?.status===200;

    // Plugins — installed version from site readme.txt vs latest from wp.org
    const plugins = await Promise.all(pluginSlugs.map(async (slug, i) => {
      const siteRes  = allPluginRes[i * 2];
      const wpOrgRes = allPluginRes[i * 2 + 1];

      let installedVersion = null;
      if (siteRes.status==='fulfilled' && siteRes.value?.status===200) {
        const txt = siteRes.value.data||'';
        const m   = txt.match(/Stable tag:\s*([^\n\r]+)/i);
        if (m) installedVersion = m[1].trim().replace(/[^0-9.]/g,'') || null;
      }

      let name=slug, latestVersion=null, author=null, rating=null, activeInstalls=null;
      if (wpOrgRes.status==='fulfilled' && wpOrgRes.value?.status===200) {
        const d = wpOrgRes.value.data;
        if (d && !d.error) {
          name          = d.name || slug;
          latestVersion = d.version || null;
          author        = (d.author||'').replace(/<[^>]+>/g,'');
          rating        = d.rating;
          activeInstalls= d.active_installs;
        }
      }

      const versionStatus = installedVersion && latestVersion
        ? (compareVersions(installedVersion, latestVersion) >= 0 ? 'current' : 'outdated')
        : installedVersion ? 'installed_only' : latestVersion ? 'latest_only' : 'unknown';

      return { slug, name, installedVersion, latestVersion, versionStatus, author, rating, activeInstalls };
    }));

    // Username security analysis
    const WEAK = ['admin','administrator','root','test','demo','wordpress','webmaster','user','guest','support'];

    // Author enumeration via /?author=N
    const authorEnum = {};
    await Promise.allSettled([1,2,3,4,5].map(async id => {
      try {
        const r = await axios.get(`${base}/?author=${id}`,
          { timeout:5000, headers:{'User-Agent':UA}, validateStatus:()=>true, maxRedirects:5 });
        const finalUrl = r.request?.res?.responseUrl || r.config?.url || '';
        if (finalUrl && !finalUrl.includes(`author=${id}`)) {
          const m = finalUrl.match(/\/author\/([^\/\?#]+)/);
          if (m) authorEnum[id] = decodeURIComponent(m[1]);
        }
      } catch {}
    }));

    const weakFound    = (users||[]).filter(u => WEAK.includes(u.slug?.toLowerCase()));
    const enumUsernames= Object.values(authorEnum);
    const allDiscovered= [...new Set([...(users||[]).map(u=>u.slug), ...enumUsernames])];

    const risks = [];
    if (weakFound.length > 0)
      risks.push({ severity:'high',   message:`Weak/default username(s) detected: ${weakFound.map(u=>u.slug).join(', ')}` });
    if (users?.length)
      risks.push({ severity:'medium', message:`${users.length} username(s) exposed via REST API (/wp-json/wp/v2/users)` });
    if (Object.keys(authorEnum).length > 0)
      risks.push({ severity:'medium', message:`Username(s) enumerable via /?author= redirect` });
    if (!risks.length)
      risks.push({ severity:'info',   message:'No obvious username vulnerabilities detected' });

    const usernameSecurity = {
      restApiExposes:    !!(users?.length),
      authorEnumeration: Object.keys(authorEnum).length > 0,
      authorEnumData:    authorEnum,
      weakUsernames:     weakFound,
      allDiscovered,
      risks,
    };

    return { detected:true, version, theme, plugins, users, usernameSecurity, restApiEnabled, xmlrpcEnabled, readmeExposed };
  } catch (e) { return { error: e.message }; }
}

// ── 15. Tech stack ────────────────────────────────────────────────────────────

async function getTechStack(url) {
  try {
    const [htmlRes, headRes] = await Promise.allSettled([axiosGet(url), axiosHead(url)]);
    const html = htmlRes.status==='fulfilled' ? (htmlRes.value.data||'') : '';
    const h    = headRes.status==='fulfilled'  ? headRes.value.headers : {};
    const tech = [];
    if (h.server)        tech.push({ name:h.server,        category:'Web Server' });
    if (h['x-powered-by']) tech.push({ name:h['x-powered-by'], category:'Runtime' });
    if (h['cf-ray'])     tech.push({ name:'Cloudflare',    category:'CDN / Security' });
    if (h['x-varnish'])  tech.push({ name:'Varnish Cache', category:'Cache' });
    const patterns = [
      [/_next\//i,'Next.js','JS Framework'],[/react(?:\.js|dom)/i,'React','JS Framework'],
      [/vue(?:\.js|\.min\.js)/i,'Vue.js','JS Framework'],[/angular(?:\.js|\/)/i,'Angular','JS Framework'],
      [/nuxt/i,'Nuxt.js','JS Framework'],[/svelte/i,'Svelte','JS Framework'],
      [/remix/i,'Remix','JS Framework'],[/astro/i,'Astro','JS Framework'],
      [/jquery(?:\.min)?\.js/i,'jQuery','JS Library'],
      [/bootstrap(?:\.min)?\.css/i,'Bootstrap','CSS Framework'],[/tailwind/i,'Tailwind CSS','CSS Framework'],
      [/wp-content/i,'WordPress','CMS'],[/drupal\.js/i,'Drupal','CMS'],[/joomla/i,'Joomla','CMS'],
      [/shopify/i,'Shopify','E-commerce'],[/woocommerce/i,'WooCommerce','E-commerce'],
      [/squarespace/i,'Squarespace','Website Builder'],[/webflow/i,'Webflow','Website Builder'],[/wix\.com/i,'Wix','Website Builder'],
      [/gatsby/i,'Gatsby','Static Site'],[/hubspot/i,'HubSpot','Marketing'],
      [/gtag\(|google-analytics|GA4/i,'Google Analytics','Analytics'],[/matomo|piwik/i,'Matomo','Analytics'],
      [/plausible/i,'Plausible','Analytics'],[/hotjar/i,'Hotjar','Analytics'],
      [/intercom/i,'Intercom','Support'],[/zendesk/i,'Zendesk','Support'],
      [/stripe\.js/i,'Stripe','Payments'],[/paypal/i,'PayPal','Payments'],
      [/recaptcha/i,'reCAPTCHA','Security'],[/fastly/i,'Fastly','CDN'],[/akamai/i,'Akamai','CDN'],
      [/amazonaws\.com/i,'Amazon AWS','Hosting'],[/googletagmanager/i,'Google Tag Manager','Analytics'],
      [/facebook\.net\/en_US\/fbevents/i,'Meta Pixel','Analytics'],
    ];
    for (const [re,name,cat] of patterns) if (re.test(html)) tech.push({ name, category:cat });
    return { technologies:[...new Map(tech.map(t=>[t.name,t])).values()] };
  } catch (e) { return { error: e.message }; }
}

// ── 16. Cookies ───────────────────────────────────────────────────────────────

async function getCookies(url) {
  try {
    const r = await axiosHead(url);
    const raw = r.headers['set-cookie'] || [];
    const cookies = raw.map(c => {
      const parts = c.split(';').map(p=>p.trim());
      const flags  = parts.slice(1).map(f=>f.toLowerCase());
      return { name:parts[0].split('=')[0], httpOnly:flags.includes('httponly'),
        secure:flags.includes('secure'), sameSite:flags.find(f=>f.startsWith('samesite='))?.split('=')[1]||null };
    });
    return { cookies, count:cookies.length };
  } catch (e) { return { error: e.message }; }
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

async function runScan(rawUrl) {
  const v = validateUrl(rawUrl);
  if (!v.valid) return { error: v.error };
  const settle = r => r.status==='fulfilled' ? r.value : { error: r.reason?.message||'Failed' };

  const [online, headers, ssl, dnsRec, dnsProp, emailSec, whois, perf, meta, commonFiles, ipInfo, socials, security, wordpress, techStack, cookies] =
    await Promise.allSettled([
      checkOnline(v.url), getHeaders(v.url), getSSL(v.hostname),
      getDNS(v.hostname), getDNSPropagation(v.hostname), getEmailSecurity(v.hostname),
      getWhois(v.hostname), getPerformance(v.url), getMeta(v.url),
      getCommonFiles(v.url), getIPInfo(v.hostname), getSocialsAndEmails(v.url),
      getSecurityChecks(v.url), detectWordPress(v.url), getTechStack(v.url), getCookies(v.url),
    ]);

  return {
    url:v.url, hostname:v.hostname, timestamp:new Date().toISOString(),
    online:settle(online), headers:settle(headers), ssl:settle(ssl),
    dns:settle(dnsRec), dnsPropagation:settle(dnsProp), emailSecurity:settle(emailSec),
    whois:settle(whois), performance:settle(perf), meta:settle(meta),
    commonFiles:settle(commonFiles), ipInfo:settle(ipInfo), socials:settle(socials),
    security:settle(security), wordpress:settle(wordpress), techStack:settle(techStack), cookies:settle(cookies),
  };
}

module.exports = { runScan, validateUrl };
