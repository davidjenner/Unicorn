import { useState, ReactNode } from 'react';

// ── Types ─────────────────────────────────────────────────────────────────────

interface OnlineResult  { status?: number; statusText?: string; responseTime?: number; error?: string }
interface HeadersResult { headers?: Record<string,string>; securityHeaders?: Record<string,boolean>; securityScore?: string; error?: string }
interface SSLResult     { subject?: Record<string,string>; issuer?: Record<string,string>; validFrom?: string; validTo?: string; daysRemaining?: number; fingerprint?: string; protocol?: string; expired?: boolean; httpsReachable?: boolean; note?: string; sans?: string[]; error?: string }
interface DNSResult     { A?: string[]; AAAA?: string[]; MX?: {exchange:string;priority:number}[]; NS?: string[]; TXT?: string[]; CAA?: {critical:number;tag:string;value:string}[]; SOA?: string; error?: string }
interface DNSPropResult { [resolver: string]: string[] | null }
interface EmailSecResult{ spf?: string|null; hasSPF?: boolean; dmarc?: string|null; hasDMARC?: boolean; dkim?: {selector:string;found:boolean}[]; hasDKIM?: boolean; mxExists?: boolean; error?: string }
interface WhoisResult   { registrar?: string|null; registrarUrl?: string|null; registrarEmail?: string|null; createdDate?: string|null; expiryDate?: string|null; updatedDate?: string|null; registrantName?: string|null; registrantOrg?: string|null; registrantEmail?: string|null; registrantCountry?: string|null; adminEmail?: string|null; techEmail?: string|null; nameServers?: string[]; status?: string[]; dnssec?: string|null; error?: string }
interface PerfResult    { totalTime?: number; httpCode?: number; size?: number; sizeKB?: string; transferRate?: string; error?: string }
interface MetaResult    { title?: string|null; description?: string|null; keywords?: string|null; robots?: string|null; viewport?: string|null; charset?: string|null; canonical?: string|null; generator?: string|null; ogTitle?: string|null; ogDescription?: string|null; ogImage?: string|null; ogType?: string|null; ogSiteName?: string|null; ogUrl?: string|null; twitterCard?: string|null; twitterSite?: string|null; twitterTitle?: string|null; hasSchema?: boolean; hasFavicon?: boolean; error?: string }
interface FileEntry     { found: boolean; size?: number; preview?: string; urlCount?: number; status?: number }
interface CommonFiles   { robots?: FileEntry; sitemap?: FileEntry; security?: FileEntry; ads?: FileEntry; humans?: FileEntry; manifest?: FileEntry; error?: string }
interface IPInfo        { ip?: string; city?: string; region?: string; country?: string; countryCode?: string; latitude?: number; longitude?: number; org?: string; asn?: string; timezone?: string; error?: string }
interface SocialsResult { emails?: string[]; socials?: Record<string,string|null>; error?: string }
interface SecurityResult{ gitExposed?: boolean; envExposed?: boolean; phpinfo?: boolean; wpLogin?: boolean; xmlrpc?: boolean; adminExposed?: boolean; readmeHtml?: boolean; licenseExposed?: boolean; backupExposed?: boolean; error?: string }
interface WPPlugin      { slug: string; name?: string; installedVersion?: string|null; latestVersion?: string|null; versionStatus?: 'current'|'outdated'|'unknown'|'installed_only'|'latest_only'; author?: string; rating?: number; activeInstalls?: number }
interface WPTheme       { slug?: string|null; name?: string|null; version?: string|null; author?: string|null; authorUri?: string|null; themeUri?: string|null; description?: string|null; license?: string|null }
interface WPUser        { id: number; name: string; slug: string; url?: string }
interface UsernameRisk  { severity: 'high'|'medium'|'low'|'info'; message: string }
interface UsernameSec   { restApiExposes?: boolean; authorEnumeration?: boolean; authorEnumData?: Record<string,string>; weakUsernames?: WPUser[]; allDiscovered?: string[]; risks?: UsernameRisk[] }
interface WPResult      { detected?: boolean; version?: string|null; theme?: WPTheme; plugins?: WPPlugin[]; users?: WPUser[]|null; usernameSecurity?: UsernameSec; restApiEnabled?: boolean; xmlrpcEnabled?: boolean; readmeExposed?: boolean; error?: string }
interface TechResult    { technologies?: {name:string;category:string}[]; error?: string }
interface CookieResult  { cookies?: {name:string;httpOnly:boolean;secure:boolean;sameSite:string|null}[]; count?: number; error?: string }

interface ScanResults {
  url: string; hostname: string; timestamp: string;
  online: OnlineResult; headers: HeadersResult; ssl: SSLResult;
  dns: DNSResult; dnsPropagation: DNSPropResult; emailSecurity: EmailSecResult;
  whois: WhoisResult; performance: PerfResult; meta: MetaResult;
  commonFiles: CommonFiles; ipInfo: IPInfo; socials: SocialsResult;
  security: SecurityResult; wordpress: WPResult; techStack: TechResult; cookies: CookieResult;
}

// ── UI primitives ─────────────────────────────────────────────────────────────

function Badge({ ok, label, warn }: { ok: boolean; label: string; warn?: boolean }) {
  const cls = ok
    ? 'bg-green-900/50 text-green-300'
    : warn
    ? 'bg-yellow-900/50 text-yellow-300'
    : 'bg-red-900/50 text-red-300';
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {ok ? '✓' : warn ? '!' : '✗'} {label}
    </span>
  );
}

function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-block bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded mr-1 mb-1 font-mono">{children}</span>;
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex gap-3 py-1.5 border-b border-slate-800 last:border-0">
      <span className="text-slate-500 text-xs w-44 shrink-0 pt-0.5">{label}</span>
      <span className="text-slate-200 text-sm break-all">{value}</span>
    </div>
  );
}

function Err({ msg }: { msg: string }) {
  return <p className="text-red-400 text-sm italic py-2">{msg}</p>;
}

function Card({ title, icon, children, defaultOpen = true }: { title: string; icon: string; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-slate-900 border border-slate-700/60 rounded-xl overflow-hidden">
      <button onClick={() => setOpen(o => !o)} className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-800/60 transition-colors">
        <span className="flex items-center gap-2 font-semibold text-slate-200 text-sm">
          <span className="text-base">{icon}</span> {title}
        </span>
        <span className="text-slate-600 text-xs">{open ? '▲' : '▼'}</span>
      </button>
      {open && <div className="px-4 pb-4 pt-1">{children}</div>}
    </div>
  );
}

function statusColor(c?: number) {
  if (!c) return 'text-slate-400';
  return c < 300 ? 'text-green-400' : c < 400 ? 'text-yellow-400' : 'text-red-400';
}

// ── Cards ─────────────────────────────────────────────────────────────────────

function OnlineCard({ data }: { data: OnlineResult }) {
  if (data.error) return <Card title="Online Status" icon="🌐"><Err msg={data.error} /></Card>;
  const ok = (data.status ?? 0) < 400;
  return (
    <Card title="Online Status" icon="🌐">
      <div className="flex items-center gap-4 flex-wrap">
        <span className={`text-4xl font-bold font-mono ${statusColor(data.status)}`}>{data.status}</span>
        <span className="text-slate-400 text-sm">{data.statusText}</span>
        <Badge ok={ok} label={ok ? 'Online' : 'Error'} />
        {data.responseTime !== undefined && <span className="text-slate-500 text-xs ml-auto">{data.responseTime}ms</span>}
      </div>
    </Card>
  );
}

function IPCard({ data }: { data: IPInfo }) {
  if (data.error && !data.ip) return <Card title="IP & Location" icon="📍"><Err msg={data.error} /></Card>;
  return (
    <Card title="IP & Location" icon="📍">
      {data.ip && <Row label="IP Address" value={<span className="font-mono">{data.ip}</span>} />}
      {data.city && <Row label="City" value={`${data.city}${data.region ? ', ' + data.region : ''}`} />}
      {data.country && <Row label="Country" value={`${data.country} ${data.countryCode ? '(' + data.countryCode + ')' : ''}`} />}
      {data.org && <Row label="ISP / Org" value={data.org} />}
      {data.asn && <Row label="ASN" value={<span className="font-mono">{data.asn}</span>} />}
      {data.timezone && <Row label="Timezone" value={data.timezone} />}
      {data.latitude && <Row label="Coordinates" value={`${data.latitude}, ${data.longitude}`} />}
      {data.error && <p className="text-yellow-500 text-xs mt-2">{data.error}</p>}
    </Card>
  );
}

function SSLCard({ data }: { data: SSLResult }) {
  if (data.error && !data.httpsReachable !== undefined) return <Card title="SSL Certificate" icon="🔒"><Err msg={data.error} /></Card>;
  if (data.note) {
    return (
      <Card title="SSL Certificate" icon="🔒">
        <Badge ok={!!data.httpsReachable} label={data.httpsReachable ? 'HTTPS Reachable' : 'HTTPS Failed'} />
        <p className="text-slate-500 text-xs mt-2">{data.note}</p>
      </Card>
    );
  }
  const days = data.daysRemaining ?? 0;
  const daysColor = days < 0 ? 'text-red-400' : days < 14 ? 'text-yellow-400' : 'text-green-400';
  return (
    <Card title="SSL Certificate" icon="🔒">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <Badge ok={!data.expired} label={data.expired ? 'Expired' : 'Valid'} />
        <span className={`text-sm font-semibold ${daysColor}`}>{days < 0 ? `Expired ${Math.abs(days)} days ago` : `${days} days remaining`}</span>
        {data.protocol && <Tag>{data.protocol}</Tag>}
      </div>
      {data.issuer?.O && <Row label="Issuer" value={data.issuer.O} />}
      {data.subject?.CN && <Row label="Common Name" value={data.subject.CN} />}
      {data.validFrom && <Row label="Valid From" value={new Date(data.validFrom).toLocaleDateString()} />}
      {data.validTo && <Row label="Expires" value={new Date(data.validTo).toLocaleDateString()} />}
      {data.sans?.length ? <Row label="SANs" value={<div className="flex flex-wrap">{data.sans.slice(0,8).map(s=><Tag key={s}>{s}</Tag>)}</div>} /> : null}
      {data.fingerprint && <Row label="Fingerprint" value={<span className="font-mono text-xs">{data.fingerprint}</span>} />}
    </Card>
  );
}

function PerfCard({ data }: { data: PerfResult }) {
  if (data.error) return <Card title="Performance" icon="⚡"><Err msg={data.error} /></Card>;
  const ms = data.totalTime ?? 0;
  const speedColor = ms < 500 ? 'text-green-400' : ms < 2000 ? 'text-yellow-400' : 'text-red-400';
  return (
    <Card title="Performance" icon="⚡">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Load Time', value: `${ms}ms`, color: speedColor },
          { label: 'HTTP Code', value: String(data.httpCode ?? '—'), color: statusColor(data.httpCode) },
          { label: 'Page Size', value: `${data.sizeKB ?? '—'}KB`, color: 'text-purple-400' },
          { label: 'KB/s', value: data.transferRate ?? '—', color: 'text-cyan-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-slate-800 rounded-lg p-3 text-center">
            <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
            <p className="text-xs text-slate-500 mt-1">{label}</p>
          </div>
        ))}
      </div>
    </Card>
  );
}

function MetaCard({ data }: { data: MetaResult }) {
  if (data.error) return <Card title="Meta / SEO" icon="🏷" defaultOpen={false}><Err msg={data.error} /></Card>;
  return (
    <Card title="Meta / SEO" icon="🏷" defaultOpen={true}>
      {data.title && <Row label="Title" value={<strong className="text-white">{data.title}</strong>} />}
      {data.description && <Row label="Description" value={data.description} />}
      {data.keywords && <Row label="Keywords" value={data.keywords} />}
      {data.canonical && <Row label="Canonical" value={<span className="font-mono text-xs text-cyan-400">{data.canonical}</span>} />}
      {data.generator && <Row label="Generator" value={<Tag>{data.generator}</Tag>} />}
      {data.charset && <Row label="Charset" value={<Tag>{data.charset}</Tag>} />}
      {data.robots && <Row label="Robots" value={<Tag>{data.robots}</Tag>} />}
      <div className="flex flex-wrap gap-2 mt-3 pt-3 border-t border-slate-800">
        <Badge ok={!!data.ogTitle} label="Open Graph" />
        <Badge ok={!!data.twitterCard} label="Twitter Card" />
        <Badge ok={!!data.hasSchema} label="Schema.org" />
        <Badge ok={!!data.hasFavicon} label="Favicon" />
      </div>
      {data.ogImage && <Row label="OG Image" value={<a href={data.ogImage} target="_blank" rel="noopener noreferrer" className="text-cyan-400 text-xs underline break-all">{data.ogImage}</a>} />}
      {(data.ogTitle || data.ogDescription) && (
        <div className="mt-3 p-3 bg-slate-800 rounded-lg border border-slate-700">
          <p className="text-xs text-slate-500 mb-1">Open Graph Preview</p>
          {data.ogSiteName && <p className="text-xs text-slate-500">{data.ogSiteName}</p>}
          {data.ogTitle && <p className="text-sm font-semibold text-white">{data.ogTitle}</p>}
          {data.ogDescription && <p className="text-xs text-slate-400 mt-1">{data.ogDescription}</p>}
        </div>
      )}
    </Card>
  );
}

function HeadersCard({ data }: { data: HeadersResult }) {
  if (data.error) return <Card title="HTTP Headers" icon="📋" defaultOpen={false}><Err msg={data.error} /></Card>;
  return (
    <Card title="HTTP Headers" icon="📋" defaultOpen={false}>
      {data.securityScore && (
        <div className="mb-3 p-3 bg-slate-800 rounded-lg">
          <p className="text-sm font-semibold text-slate-300 mb-2">Security Headers: {data.securityScore}</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.securityHeaders ?? {}).map(([k, v]) => <Badge key={k} ok={v} label={k.replace(/-/g,' ')} />)}
          </div>
        </div>
      )}
      {data.headers && Object.entries(data.headers).map(([k, v]) => (
        <Row key={k} label={k} value={<span className="font-mono text-xs">{v}</span>} />
      ))}
    </Card>
  );
}

function DNSCard({ data }: { data: DNSResult }) {
  if (data.error) return <Card title="DNS Records" icon="🔍" defaultOpen={false}><Err msg={data.error} /></Card>;
  return (
    <Card title="DNS Records" icon="🔍">
      {data.A?.length ? <Row label="A (IPv4)" value={<>{data.A.map(ip=><Tag key={ip}>{ip}</Tag>)}</>} /> : null}
      {data.AAAA?.length ? <Row label="AAAA (IPv6)" value={<>{data.AAAA.map(ip=><Tag key={ip}>{ip}</Tag>)}</>} /> : null}
      {data.MX?.length ? <Row label="MX (Mail)" value={<>{data.MX.sort((a,b)=>a.priority-b.priority).map(r=><Tag key={r.exchange}>{r.priority} {r.exchange}</Tag>)}</>} /> : null}
      {data.NS?.length ? <Row label="NS (Nameserver)" value={<>{data.NS.map(ns=><Tag key={ns}>{ns}</Tag>)}</>} /> : null}
      {data.CAA?.length ? <Row label="CAA" value={<>{(data.CAA as any[]).map((c:any,i:number)=><Tag key={i}>{typeof c==='object'?`${c.tag} "${c.value}"`:c}</Tag>)}</>} /> : null}
      {data.SOA ? <Row label="SOA" value={<span className="font-mono text-xs">{data.SOA as any}</span>} /> : null}
      {data.TXT?.length ? (
        <div className="mt-2">
          <p className="text-slate-500 text-xs mb-1">TXT Records</p>
          {data.TXT.map((t,i)=><p key={i} className="font-mono text-xs text-slate-300 bg-slate-800 rounded p-2 mb-1 break-all">{t}</p>)}
        </div>
      ) : null}
    </Card>
  );
}

function DNSPropCard({ data }: { data: DNSPropResult }) {
  const entries = Object.entries(data);
  if (!entries.length) return null;
  const ips = [...new Set(entries.flatMap(([,v])=>v||[]))];
  const allAgree = entries.every(([,v])=>v?.length && JSON.stringify(v?.sort())===JSON.stringify((ips).sort()));
  return (
    <Card title="DNS Propagation" icon="🌍" defaultOpen={false}>
      <div className="flex items-center gap-2 mb-3">
        <Badge ok={allAgree} label={allAgree ? 'Fully propagated' : 'Inconsistent'} warn={!allAgree} />
        <span className="text-xs text-slate-500">(whatmydns check across {entries.length} resolvers)</span>
      </div>
      <div className="space-y-1">
        {entries.map(([name, ips]) => (
          <div key={name} className="flex items-center gap-3 py-1 border-b border-slate-800 last:border-0">
            <span className="text-slate-500 text-xs w-48 shrink-0">{name}</span>
            {ips === null
              ? <span className="text-red-400 text-xs">Timeout</span>
              : ips.length === 0
              ? <span className="text-slate-600 text-xs">No record</span>
              : <div className="flex flex-wrap gap-1">{ips.map(ip=><Tag key={ip}>{ip}</Tag>)}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
}

function EmailSecCard({ data }: { data: EmailSecResult }) {
  if (data.error) return <Card title="Email Security" icon="📧" defaultOpen={false}><Err msg={data.error} /></Card>;
  return (
    <Card title="Email Security" icon="📧">
      <div className="flex flex-wrap gap-2 mb-3">
        <Badge ok={!!data.hasSPF}   label="SPF" />
        <Badge ok={!!data.hasDMARC} label="DMARC" />
        <Badge ok={!!data.hasDKIM}  label="DKIM" />
        <Badge ok={!!data.mxExists} label="MX Records" />
      </div>
      {data.spf   && <Row label="SPF Record"   value={<span className="font-mono text-xs break-all">{data.spf}</span>} />}
      {data.dmarc && <Row label="DMARC Record" value={<span className="font-mono text-xs break-all">{data.dmarc}</span>} />}
      {data.dkim?.length ? <Row label="DKIM Selectors" value={<>{data.dkim.map(d=><Tag key={d.selector}>{d.selector}</Tag>)}</>} /> : null}
    </Card>
  );
}

function WhoisCard({ data }: { data: WhoisResult }) {
  if (data.error) return <Card title="WHOIS" icon="📇" defaultOpen={false}><Err msg={data.error} /></Card>;
  const fmt = (s?: string|null) => { try { return s ? new Date(s).toLocaleDateString() : null; } catch { return s; } };
  return (
    <Card title="WHOIS" icon="📇">
      {data.registrar && <Row label="Registrar" value={data.registrarUrl ? <a href={data.registrarUrl} target="_blank" rel="noopener noreferrer" className="text-cyan-400 underline">{data.registrar}</a> : data.registrar} />}
      {data.registrarEmail && <Row label="Registrar Abuse" value={data.registrarEmail} />}
      {data.registrantName && <Row label="Registrant Name" value={data.registrantName} />}
      {data.registrantOrg && <Row label="Registrant Org" value={data.registrantOrg} />}
      {data.registrantEmail && <Row label="Registrant Email" value={data.registrantEmail} />}
      {data.registrantCountry && <Row label="Country" value={data.registrantCountry} />}
      {data.adminEmail && <Row label="Admin Email" value={data.adminEmail} />}
      {data.techEmail && <Row label="Tech Email" value={data.techEmail} />}
      {data.createdDate && <Row label="Registered" value={fmt(data.createdDate) ?? data.createdDate} />}
      {data.updatedDate && <Row label="Updated" value={fmt(data.updatedDate) ?? data.updatedDate} />}
      {data.expiryDate && <Row label="Expires" value={fmt(data.expiryDate) ?? data.expiryDate} />}
      {data.dnssec && <Row label="DNSSEC" value={<Badge ok={data.dnssec === 'Signed'} label={data.dnssec} />} />}
      {data.nameServers?.length ? <Row label="Name Servers" value={<>{data.nameServers.map(ns=><Tag key={ns}>{ns}</Tag>)}</>} /> : null}
      {data.status?.length ? <Row label="Status" value={<>{data.status.map(s=><Tag key={s}>{s}</Tag>)}</>} /> : null}
    </Card>
  );
}

function CommonFilesCard({ data }: { data: CommonFiles }) {
  if (data.error) return <Card title="Common Files" icon="📁" defaultOpen={false}><Err msg={data.error} /></Card>;
  const entries = [
    { key: 'robots',   label: 'robots.txt',          entry: data.robots },
    { key: 'sitemap',  label: 'sitemap.xml',          entry: data.sitemap },
    { key: 'security', label: '.well-known/security.txt', entry: data.security },
    { key: 'ads',      label: 'ads.txt',              entry: data.ads },
    { key: 'humans',   label: 'humans.txt',           entry: data.humans },
    { key: 'manifest', label: 'manifest.json',        entry: data.manifest },
  ];
  return (
    <Card title="Common Files" icon="📁" defaultOpen={false}>
      <div className="space-y-3">
        {entries.map(({ key, label, entry }) => (
          <div key={key}>
            <div className="flex items-center gap-2 mb-1">
              <Badge ok={!!entry?.found} label={label} />
              {entry?.found && entry.size !== undefined && <span className="text-slate-500 text-xs">{(entry.size/1024).toFixed(1)}KB</span>}
              {entry?.found && key === 'sitemap' && entry.urlCount !== undefined && entry.urlCount > 0 && <span className="text-cyan-400 text-xs">{entry.urlCount} URLs</span>}
            </div>
            {entry?.found && entry.preview && (
              <pre className="bg-slate-800 text-slate-400 text-xs p-2 rounded overflow-x-auto max-h-32">{entry.preview}{entry.size && entry.size > 600 ? '\n…' : ''}</pre>
            )}
          </div>
        ))}
      </div>
    </Card>
  );
}

function TechCard({ data }: { data: TechResult }) {
  if (data.error) return <Card title="Tech Stack" icon="🛠" defaultOpen={false}><Err msg={data.error} /></Card>;
  if (!data.technologies?.length) return <Card title="Tech Stack" icon="🛠" defaultOpen={false}><p className="text-slate-500 text-sm">None detected.</p></Card>;
  const grouped = data.technologies.reduce<Record<string,string[]>>((acc,t) => { (acc[t.category]=acc[t.category]||[]).push(t.name); return acc; }, {});
  return (
    <Card title="Tech Stack" icon="🛠">
      <div className="space-y-3">
        {Object.entries(grouped).map(([cat, names]) => (
          <div key={cat}>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{cat}</p>
            <div className="flex flex-wrap">{names.map(n=><Tag key={n}>{n}</Tag>)}</div>
          </div>
        ))}
      </div>
    </Card>
  );
}

function SocialsCard({ data }: { data: SocialsResult }) {
  if (data.error) return <Card title="Socials & Emails" icon="🔗" defaultOpen={false}><Err msg={data.error} /></Card>;
  const socials = Object.entries(data.socials ?? {}).filter(([,v]) => !!v);
  return (
    <Card title="Socials & Emails" icon="🔗" defaultOpen={false}>
      {data.emails?.length ? (
        <div className="mb-3">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Email Addresses</p>
          <div className="flex flex-wrap">{data.emails.map(e=><Tag key={e}>{e}</Tag>)}</div>
        </div>
      ) : <p className="text-slate-500 text-sm mb-3">No email addresses found in page HTML.</p>}
      {socials.length ? (
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Social Profiles</p>
          {socials.map(([platform, url]) => (
            <Row key={platform} label={platform.charAt(0).toUpperCase()+platform.slice(1)}
              value={<a href={url!} target="_blank" rel="noopener noreferrer" className="text-cyan-400 underline text-xs">{url}</a>} />
          ))}
        </div>
      ) : null}
    </Card>
  );
}

function SecurityCard({ data }: { data: SecurityResult }) {
  if (data.error) return <Card title="Security Checks" icon="🔐" defaultOpen={false}><Err msg={data.error} /></Card>;
  const checks = [
    { key: 'gitExposed',     label: '.git/ exposed',       bad: true },
    { key: 'envExposed',     label: '.env exposed',         bad: true },
    { key: 'phpinfo',        label: 'phpinfo.php exposed',  bad: true },
    { key: 'backupExposed',  label: 'backup.zip exposed',   bad: true },
    { key: 'readmeHtml',     label: 'readme.html exposed',  bad: true },
    { key: 'licenseExposed', label: 'license.txt exposed',  bad: false },
    { key: 'wpLogin',        label: 'WP login accessible',  bad: false },
    { key: 'xmlrpc',         label: 'xmlrpc.php enabled',   bad: false },
    { key: 'adminExposed',   label: '/admin accessible',    bad: false },
  ];
  const exposed = checks.filter(c => (data as any)[c.key]);
  const critical = exposed.filter(c => c.bad);
  return (
    <Card title="Security Checks" icon="🔐" defaultOpen={false}>
      {critical.length > 0 && (
        <div className="mb-3 p-3 bg-red-950/40 border border-red-800/50 rounded-lg">
          <p className="text-red-400 text-xs font-semibold mb-1">⚠ {critical.length} critical exposure(s) detected</p>
        </div>
      )}
      <div className="flex flex-wrap gap-2">
        {checks.map(({ key, label, bad }) => {
          const found = (data as any)[key];
          return <Badge key={key} ok={!found} warn={found && !bad} label={label} />;
        })}
      </div>
    </Card>
  );
}

function VersionBadge({ p }: { p: WPPlugin }) {
  if (p.versionStatus === 'outdated') {
    return (
      <div className="text-right shrink-0">
        <span className="inline-block bg-red-900/60 text-red-300 text-xs px-2 py-0.5 rounded font-mono">
          {p.installedVersion} → {p.latestVersion}
        </span>
        <p className="text-red-400 text-xs mt-0.5 font-semibold">Outdated</p>
      </div>
    );
  }
  if (p.versionStatus === 'current') {
    return (
      <div className="text-right shrink-0">
        <span className="inline-block bg-green-900/40 text-green-300 text-xs px-2 py-0.5 rounded font-mono">{p.installedVersion}</span>
        <p className="text-green-500 text-xs mt-0.5">Up to date</p>
      </div>
    );
  }
  if (p.versionStatus === 'latest_only' && p.latestVersion) {
    return (
      <div className="text-right shrink-0">
        <Tag>{p.latestVersion}</Tag>
        <p className="text-slate-500 text-xs mt-0.5">Latest (installed unknown)</p>
      </div>
    );
  }
  if (p.versionStatus === 'installed_only' && p.installedVersion) {
    return (
      <div className="text-right shrink-0">
        <Tag>{p.installedVersion}</Tag>
        <p className="text-slate-500 text-xs mt-0.5">Not on wp.org</p>
      </div>
    );
  }
  return <div className="text-right shrink-0"><span className="text-slate-600 text-xs">Version unknown</span></div>;
}

function WordPressCard({ data }: { data: WPResult }) {
  if (data.error) return <Card title="WordPress" icon="🔷" defaultOpen={false}><Err msg={data.error} /></Card>;
  if (!data.detected) return <Card title="WordPress" icon="🔷" defaultOpen={false}><p className="text-slate-500 text-sm">Not detected.</p></Card>;

  const outdated = data.plugins?.filter(p => p.versionStatus === 'outdated') ?? [];
  const highRisks = data.usernameSecurity?.risks?.filter(r => r.severity === 'high') ?? [];

  return (
    <Card title="WordPress" icon="🔷">
      {/* Summary badges */}
      <div className="flex flex-wrap gap-2 mb-4">
        <Badge ok={true} label="WordPress Detected" />
        {data.version && <Tag>Core v{data.version}</Tag>}
        <Badge ok={!!data.restApiEnabled} label="REST API" />
        <Badge ok={!data.xmlrpcEnabled} warn={!!data.xmlrpcEnabled} label="xmlrpc.php" />
        <Badge ok={!data.readmeExposed} warn={!!data.readmeExposed} label="readme.html" />
        {outdated.length > 0 && (
          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium bg-red-900/50 text-red-300">
            ⚠ {outdated.length} outdated plugin{outdated.length !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      {/* Theme */}
      {data.theme?.slug && (
        <div className="mb-5">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Active Theme</p>
          <div className="bg-slate-800 rounded-lg p-3">
            <p className="text-white font-semibold">{data.theme.name || data.theme.slug}</p>
            {data.theme.version && <p className="text-slate-400 text-xs mt-0.5">v{data.theme.version}</p>}
            {data.theme.author && <p className="text-slate-400 text-xs">By {data.theme.author}</p>}
            {data.theme.description && <p className="text-slate-500 text-xs mt-1 italic">{data.theme.description}</p>}
            {data.theme.themeUri && (
              <a href={data.theme.themeUri} target="_blank" rel="noopener noreferrer" className="text-cyan-400 text-xs underline mt-1 block">{data.theme.themeUri}</a>
            )}
          </div>
        </div>
      )}

      {/* Plugins with version comparison */}
      {data.plugins?.length ? (
        <div className="mb-5">
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs text-slate-500 uppercase tracking-wider">
              Plugins ({data.plugins.length})
            </p>
            {outdated.length > 0 && (
              <span className="text-red-400 text-xs">{outdated.length} need updating</span>
            )}
          </div>
          <div className="space-y-2">
            {data.plugins
              .sort((a, b) => (a.versionStatus === 'outdated' ? -1 : b.versionStatus === 'outdated' ? 1 : 0))
              .map(p => (
                <div key={p.slug}
                  className={`rounded-lg p-3 flex items-start justify-between gap-3 ${p.versionStatus === 'outdated' ? 'bg-red-950/30 border border-red-800/40' : 'bg-slate-800'}`}>
                  <div className="min-w-0">
                    <p className="text-slate-200 text-sm font-medium truncate">{p.name || p.slug}</p>
                    {p.author && <p className="text-slate-500 text-xs">By {p.author.replace(/<[^>]+>/g,'')}</p>}
                    {p.activeInstalls != null && (
                      <p className="text-slate-600 text-xs">{(p.activeInstalls as number).toLocaleString()}+ installs</p>
                    )}
                  </div>
                  <VersionBadge p={p} />
                </div>
              ))}
          </div>
        </div>
      ) : null}

      {/* Username Security */}
      {data.usernameSecurity && (
        <div className="mb-5">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">Username Security</p>

          {/* Risk items */}
          <div className="space-y-2 mb-3">
            {data.usernameSecurity.risks?.map((r, i) => {
              const colour =
                r.severity === 'high'   ? 'bg-red-950/40 border-red-800/50 text-red-300' :
                r.severity === 'medium' ? 'bg-yellow-950/40 border-yellow-800/50 text-yellow-300' :
                r.severity === 'low'    ? 'bg-blue-950/40 border-blue-800/50 text-blue-300' :
                                          'bg-slate-800 border-slate-700 text-slate-400';
              const icon = r.severity === 'high' ? '🔴' : r.severity === 'medium' ? '🟡' : r.severity === 'low' ? '🔵' : '✓';
              return (
                <div key={i} className={`flex items-start gap-2 p-2.5 rounded-lg border text-xs ${colour}`}>
                  <span>{icon}</span>
                  <span>{r.message}</span>
                </div>
              );
            })}
          </div>

          {/* Discovered usernames */}
          {data.usernameSecurity.allDiscovered?.length ? (
            <div className="mb-3">
              <p className="text-xs text-slate-600 mb-1">Discovered usernames</p>
              <div className="flex flex-wrap gap-1">
                {data.usernameSecurity.allDiscovered.map(u => {
                  const isWeak = data.usernameSecurity?.weakUsernames?.some(w => w.slug === u);
                  return (
                    <span key={u}
                      className={`text-xs px-2 py-0.5 rounded font-mono ${isWeak ? 'bg-red-900/50 text-red-300' : 'bg-slate-800 text-slate-300'}`}>
                      {isWeak ? '⚠ ' : ''}{u}
                    </span>
                  );
                })}
              </div>
            </div>
          ) : null}

          {/* Author enumeration findings */}
          {data.usernameSecurity.authorEnumeration && Object.keys(data.usernameSecurity.authorEnumData ?? {}).length > 0 && (
            <div>
              <p className="text-xs text-slate-600 mb-1">Author enumeration (/?author=N)</p>
              <div className="space-y-1">
                {Object.entries(data.usernameSecurity.authorEnumData ?? {}).map(([id, slug]) => (
                  <div key={id} className="flex items-center gap-3 font-mono text-xs bg-slate-800 rounded px-2 py-1">
                    <span className="text-slate-500">ID {id}</span>
                    <span className="text-yellow-300">{slug}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Full user list from REST API */}
      {data.users?.length ? (
        <div>
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">REST API User List</p>
          <div className="space-y-1">
            {data.users.map(u => (
              <div key={u.id} className="flex items-center gap-3 py-1.5 border-b border-slate-800 last:border-0">
                <span className="text-slate-600 text-xs w-6 text-right font-mono">{u.id}</span>
                <span className="text-slate-200 text-sm">{u.name}</span>
                <Tag>{u.slug}</Tag>
              </div>
            ))}
          </div>
        </div>
      ) : null}
    </Card>
  );
}

function CookiesCard({ data }: { data: CookieResult }) {
  if (data.error) return <Card title="Cookies" icon="🍪" defaultOpen={false}><Err msg={data.error} /></Card>;
  if (!data.cookies?.length) return <Card title="Cookies" icon="🍪" defaultOpen={false}><p className="text-slate-500 text-sm">No cookies set.</p></Card>;
  return (
    <Card title="Cookies" icon="🍪" defaultOpen={false}>
      <div className="space-y-2">
        {data.cookies?.map((c,i) => (
          <div key={i} className="bg-slate-800 rounded-lg p-3">
            <p className="font-mono text-sm text-purple-300 mb-2">{c.name}</p>
            <div className="flex gap-2 flex-wrap">
              <Badge ok={c.httpOnly} label="HttpOnly" />
              <Badge ok={c.secure} label="Secure" />
              {c.sameSite && <Badge ok={c.sameSite.toLowerCase() !== 'none'} label={`SameSite=${c.sameSite}`} />}
            </div>
          </div>
        ))}
      </div>
    </Card>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) { setError('Please enter a URL.'); return; }
    if (!consent) { setError('You must confirm authorization to scan this website.'); return; }
    setScanning(true); setError(null); setResults(null);
    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), consent }),
      });
      const data = await resp.json();
      if (!resp.ok) { setError(data.error || 'Scan failed.'); return; }
      setResults(data);
    } catch { setError('Could not reach the scanner API. Is the server running?'); }
    finally { setScanning(false); }
  };

  return (
    <div className="min-h-screen" style={{ background: 'linear-gradient(135deg, #09090f 0%, #0f0f1e 100%)' }}>
      <header className="border-b border-slate-800 px-6 py-4 flex items-center gap-3">
        <span className="text-3xl">🦄</span>
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Unicorn Scanner</h1>
          <p className="text-xs text-slate-500">Authorized website intelligence</p>
        </div>
        <span className="ml-auto text-xs text-slate-600 bg-slate-800 px-2 py-1 rounded">v2.1</span>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-8">
        {/* Form */}
        <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 mb-8 shadow-xl shadow-purple-950/20">
          <h2 className="text-slate-300 font-semibold mb-4 text-xs uppercase tracking-widest">Target URL</h2>
          <div className="flex gap-3 mb-4">
            <input type="text" placeholder="https://example.com" value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && consent && handleScan()}
              disabled={scanning}
              className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 transition-colors font-mono disabled:opacity-50" />
            <button onClick={handleScan} disabled={scanning || !consent}
              className="px-6 py-3 rounded-lg font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: scanning ? '#4c1d95' : 'linear-gradient(135deg, #7c3aed, #6d28d9)' }}>
              {scanning ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>Scanning…
                </span>
              ) : 'Scan'}
            </button>
          </div>
          <label className="flex items-start gap-3 cursor-pointer group">
            <div className="relative mt-0.5" onClick={() => setConsent(c => !c)}>
              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all cursor-pointer ${consent ? 'bg-purple-600 border-purple-600' : 'border-slate-600 bg-slate-800 group-hover:border-slate-500'}`}>
                {consent && <svg viewBox="0 0 12 10" fill="none" className="w-3 h-3"><path d="M1 5l3 3 7-7" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
              </div>
            </div>
            <span className="text-sm text-slate-400 leading-relaxed">
              I confirm I have <span className="text-white font-medium">explicit authorization</span> to scan this website. Unauthorized scanning may be illegal. For authorized security testing, research, and reconnaissance only.
            </span>
          </label>
          {error && <div className="mt-4 p-3 bg-red-950/50 border border-red-800 rounded-lg text-red-300 text-sm">{error}</div>}
        </div>

        {/* Loading */}
        {scanning && (
          <div className="text-center py-16">
            <div className="inline-flex flex-col items-center gap-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-full border-4 border-slate-700 border-t-purple-500 animate-spin"/>
                <span className="absolute inset-0 flex items-center justify-center text-2xl">🦄</span>
              </div>
              <p className="text-slate-400 animate-pulse">Running 16 scan modules in parallel…</p>
              <div className="flex flex-wrap gap-1.5 justify-center text-xs text-slate-600 max-w-lg">
                {['Online','SSL','DNS','Propagation','WHOIS','Headers','Performance','Meta/SEO','IP Info','Email Security','Common Files','WordPress','Tech Stack','Cookies','Socials','Security'].map(s=>(
                  <span key={s} className="bg-slate-800 px-2 py-0.5 rounded">{s}</span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {results && !scanning && (
          <>
            <div className="flex items-center justify-between mb-5">
              <div>
                <p className="text-xs text-slate-500">Results for</p>
                <p className="font-mono text-purple-300 font-semibold text-lg">{results.hostname}</p>
              </div>
              <p className="text-xs text-slate-600">{new Date(results.timestamp).toLocaleString()}</p>
            </div>

            {/* Row 1: status + IP */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <OnlineCard data={results.online} />
              <IPCard data={results.ipInfo} />
            </div>

            {/* Row 2: SSL + perf */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <SSLCard data={results.ssl} />
              <PerfCard data={results.performance} />
            </div>

            {/* Meta/SEO full width */}
            <div className="mb-4"><MetaCard data={results.meta} /></div>

            {/* Row 3: tech + email security */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <TechCard data={results.techStack} />
              <EmailSecCard data={results.emailSecurity} />
            </div>

            {/* Remaining sections stacked */}
            <div className="space-y-4">
              <WordPressCard data={results.wordpress} />
              <DNSCard data={results.dns} />
              <DNSPropCard data={results.dnsPropagation} />
              <WhoisCard data={results.whois} />
              <CommonFilesCard data={results.commonFiles} />
              <SocialsCard data={results.socials} />
              <SecurityCard data={results.security} />
              <HeadersCard data={results.headers} />
              <CookiesCard data={results.cookies} />
            </div>
          </>
        )}
      </main>

      <footer className="border-t border-slate-800 px-6 py-4 text-center text-xs text-slate-600">
        Unicorn Scanner — for authorized use only. Never scan systems without permission.
      </footer>
    </div>
  );
}
