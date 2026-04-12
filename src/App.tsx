import { useState, ReactNode } from 'react';

// ── Types ────────────────────────────────────────────────────────────────────

interface OnlineResult   { status?: number; statusText?: string; responseTime?: number; error?: string }
interface HeadersResult  { headers?: Record<string,string>; securityHeaders?: Record<string,boolean>; securityScore?: string; error?: string }
interface SSLResult      { subject?: Record<string,string>; issuer?: Record<string,string>; validFrom?: string; validTo?: string; daysRemaining?: number; fingerprint?: string; protocol?: string; expired?: boolean; error?: string }
interface DNSResult      { A?: string[]; AAAA?: string[]; MX?: {exchange:string;priority:number}[]; NS?: string[]; TXT?: string[]; error?: string }
interface WhoisResult    { registrar?: string; createdDate?: string; expiryDate?: string; updatedDate?: string; registrantOrg?: string; registrantCountry?: string; nameServers?: string[]; status?: string[]; error?: string }
interface PerfResult     { totalTime?: number; httpCode?: number; size?: number; sizeKB?: string; transferRate?: string; error?: string }
interface WPResult       { detected?: boolean; version?: string|null; plugins?: string[]; theme?: string|null; error?: string }
interface CookieResult   { cookies?: {name:string;httpOnly:boolean;secure:boolean;sameSite:string|null}[]; count?: number; error?: string }
interface TechResult     { technologies?: {name:string;category:string}[]; error?: string }

interface ScanResults {
  url: string;
  hostname: string;
  timestamp: string;
  online: OnlineResult;
  headers: HeadersResult;
  ssl: SSLResult;
  dns: DNSResult;
  whois: WhoisResult;
  performance: PerfResult;
  wordpress: WPResult;
  cookies: CookieResult;
  techStack: TechResult;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function statusColor(code?: number) {
  if (!code) return 'text-gray-400';
  if (code < 300) return 'text-green-400';
  if (code < 400) return 'text-yellow-400';
  return 'text-red-400';
}

function Badge({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${ok ? 'bg-green-900/50 text-green-300' : 'bg-red-900/50 text-red-300'}`}>
      {ok ? '✓' : '✗'} {label}
    </span>
  );
}

function Tag({ children }: { children: ReactNode }) {
  return <span className="inline-block bg-slate-800 text-slate-300 text-xs px-2 py-0.5 rounded mr-1 mb-1 font-mono">{children}</span>;
}

function SectionCard({ title, icon, children, defaultOpen = true }: { title: string; icon: string; children: ReactNode; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 hover:bg-slate-800 transition-colors"
      >
        <span className="flex items-center gap-2 font-semibold text-slate-200">
          <span className="text-lg">{icon}</span> {title}
        </span>
        <span className="text-slate-500 text-sm">{open ? '▲' : '▼'}</span>
      </button>
      {open && <div className="px-4 pb-4 pt-1">{children}</div>}
    </div>
  );
}

function ErrorNote({ msg }: { msg: string }) {
  return <p className="text-red-400 text-sm italic">{msg}</p>;
}

function Row({ label, value }: { label: string; value: ReactNode }) {
  return (
    <div className="flex gap-3 py-1.5 border-b border-slate-800 last:border-0">
      <span className="text-slate-500 text-sm w-40 shrink-0">{label}</span>
      <span className="text-slate-200 text-sm break-all">{value}</span>
    </div>
  );
}

// ── Result cards ─────────────────────────────────────────────────────────────

function OnlineCard({ data }: { data: OnlineResult }) {
  if (data.error) return <SectionCard title="Online Status" icon="🌐"><ErrorNote msg={data.error} /></SectionCard>;
  const ok = (data.status ?? 0) < 400;
  return (
    <SectionCard title="Online Status" icon="🌐">
      <div className="flex items-center gap-4 flex-wrap">
        <span className={`text-4xl font-bold ${statusColor(data.status)}`}>{data.status}</span>
        <span className="text-slate-400">{data.statusText}</span>
        <Badge ok={ok} label={ok ? 'Online' : 'Error'} />
        {data.responseTime !== undefined && (
          <span className="text-slate-400 text-sm ml-auto">{data.responseTime}ms response</span>
        )}
      </div>
    </SectionCard>
  );
}

function SSLCard({ data }: { data: SSLResult }) {
  if (data.error) return <SectionCard title="SSL Certificate" icon="🔒"><ErrorNote msg={data.error} /></SectionCard>;
  const days = data.daysRemaining ?? 0;
  const daysColor = days < 0 ? 'text-red-400' : days < 14 ? 'text-yellow-400' : 'text-green-400';
  return (
    <SectionCard title="SSL Certificate" icon="🔒">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <Badge ok={!data.expired} label={data.expired ? 'Expired' : 'Valid'} />
        <span className={`text-sm font-semibold ${daysColor}`}>
          {days < 0 ? `Expired ${Math.abs(days)} days ago` : `${days} days remaining`}
        </span>
        {data.protocol && <Tag>{data.protocol}</Tag>}
      </div>
      {data.issuer?.O && <Row label="Issuer" value={data.issuer.O} />}
      {data.subject?.CN && <Row label="Domain" value={data.subject.CN} />}
      {data.validFrom && <Row label="Valid From" value={new Date(data.validFrom).toLocaleDateString()} />}
      {data.validTo && <Row label="Valid To" value={new Date(data.validTo).toLocaleDateString()} />}
      {data.fingerprint && <Row label="Fingerprint" value={<span className="font-mono text-xs">{data.fingerprint}</span>} />}
    </SectionCard>
  );
}

function HeadersCard({ data }: { data: HeadersResult }) {
  if (data.error) return <SectionCard title="HTTP Headers" icon="📋"><ErrorNote msg={data.error} /></SectionCard>;
  return (
    <SectionCard title="HTTP Headers" icon="📋">
      {data.securityScore && (
        <div className="mb-3 p-3 bg-slate-800 rounded-lg">
          <p className="text-sm font-semibold text-slate-300 mb-2">Security Headers: {data.securityScore}</p>
          <div className="flex flex-wrap gap-2">
            {Object.entries(data.securityHeaders ?? {}).map(([k, v]) => (
              <Badge key={k} ok={v} label={k.replace(/-/g, ' ')} />
            ))}
          </div>
        </div>
      )}
      {data.headers && Object.entries(data.headers).map(([k, v]) => (
        <Row key={k} label={k} value={<span className="font-mono text-xs">{v}</span>} />
      ))}
    </SectionCard>
  );
}

function DNSCard({ data }: { data: DNSResult }) {
  if (data.error) return <SectionCard title="DNS Records" icon="🔍"><ErrorNote msg={data.error} /></SectionCard>;
  return (
    <SectionCard title="DNS Records" icon="🔍">
      {data.A?.length ? <Row label="A (IPv4)" value={<>{data.A.map(ip => <Tag key={ip}>{ip}</Tag>)}</>} /> : null}
      {data.AAAA?.length ? <Row label="AAAA (IPv6)" value={<>{data.AAAA.map(ip => <Tag key={ip}>{ip}</Tag>)}</>} /> : null}
      {data.MX?.length ? (
        <Row label="MX (Mail)" value={
          <>{data.MX.sort((a,b) => a.priority - b.priority).map(r => <Tag key={r.exchange}>{r.priority} {r.exchange}</Tag>)}</>
        } />
      ) : null}
      {data.NS?.length ? <Row label="NS (Nameserver)" value={<>{data.NS.map(ns => <Tag key={ns}>{ns}</Tag>)}</>} /> : null}
      {data.TXT?.length ? (
        <div className="mt-2">
          <p className="text-slate-500 text-sm mb-1">TXT Records</p>
          {data.TXT.map((t, i) => <p key={i} className="font-mono text-xs text-slate-300 bg-slate-800 rounded p-2 mb-1 break-all">{t}</p>)}
        </div>
      ) : null}
      {!data.A?.length && !data.NS?.length && !data.MX?.length && <p className="text-slate-500 text-sm">No records found.</p>}
    </SectionCard>
  );
}

function WhoisCard({ data }: { data: WhoisResult }) {
  if (data.error) return <SectionCard title="WHOIS" icon="📇"><ErrorNote msg={data.error} /></SectionCard>;
  const fmt = (s?: string|null) => s ? new Date(s).toLocaleDateString() : null;
  return (
    <SectionCard title="WHOIS" icon="📇">
      {data.registrar && <Row label="Registrar" value={data.registrar} />}
      {data.registrantOrg && <Row label="Registrant Org" value={data.registrantOrg} />}
      {data.registrantCountry && <Row label="Country" value={data.registrantCountry} />}
      {data.createdDate && <Row label="Registered" value={fmt(data.createdDate) ?? data.createdDate} />}
      {data.updatedDate && <Row label="Updated" value={fmt(data.updatedDate) ?? data.updatedDate} />}
      {data.expiryDate && <Row label="Expires" value={fmt(data.expiryDate) ?? data.expiryDate} />}
      {data.nameServers?.length ? (
        <Row label="Name Servers" value={<>{data.nameServers.map(ns => <Tag key={ns}>{ns}</Tag>)}</>} />
      ) : null}
      {data.status?.length ? (
        <Row label="Status" value={<>{data.status.map(s => <Tag key={s}>{s}</Tag>)}</>} />
      ) : null}
    </SectionCard>
  );
}

function PerformanceCard({ data }: { data: PerfResult }) {
  if (data.error) return <SectionCard title="Performance" icon="⚡"><ErrorNote msg={data.error} /></SectionCard>;
  const speedColor = (ms?: number) => !ms ? 'text-slate-400' : ms < 500 ? 'text-green-400' : ms < 2000 ? 'text-yellow-400' : 'text-red-400';
  return (
    <SectionCard title="Performance" icon="⚡">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <p className={`text-2xl font-bold ${speedColor(data.totalTime)}`}>{data.totalTime}ms</p>
          <p className="text-xs text-slate-500 mt-1">Load Time</p>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <p className={`text-2xl font-bold ${statusColor(data.httpCode)}`}>{data.httpCode}</p>
          <p className="text-xs text-slate-500 mt-1">HTTP Code</p>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-purple-400">{data.sizeKB ?? '—'}KB</p>
          <p className="text-xs text-slate-500 mt-1">Page Size</p>
        </div>
        <div className="bg-slate-800 rounded-lg p-3 text-center">
          <p className="text-2xl font-bold text-cyan-400">{data.transferRate ?? '—'}</p>
          <p className="text-xs text-slate-500 mt-1">KB/s</p>
        </div>
      </div>
    </SectionCard>
  );
}

function WordPressCard({ data }: { data: WPResult }) {
  if (data.error) return <SectionCard title="WordPress" icon="🔷" defaultOpen={false}><ErrorNote msg={data.error} /></SectionCard>;
  if (!data.detected) return (
    <SectionCard title="WordPress" icon="🔷" defaultOpen={false}>
      <p className="text-slate-500 text-sm">No WordPress installation detected.</p>
    </SectionCard>
  );
  return (
    <SectionCard title="WordPress" icon="🔷">
      <div className="flex items-center gap-3 mb-3 flex-wrap">
        <Badge ok={true} label="WordPress Detected" />
        {data.version && <Tag>v{data.version}</Tag>}
        {data.theme && <span className="text-sm text-slate-400">Theme: <Tag>{data.theme}</Tag></span>}
      </div>
      {data.plugins?.length ? (
        <>
          <p className="text-slate-500 text-sm mb-2">Detected Plugins ({data.plugins.length})</p>
          <div className="flex flex-wrap">{data.plugins.map(p => <Tag key={p}>{p}</Tag>)}</div>
        </>
      ) : <p className="text-slate-500 text-sm">No plugins detected in page HTML.</p>}
    </SectionCard>
  );
}

function CookiesCard({ data }: { data: CookieResult }) {
  if (data.error) return <SectionCard title="Cookies" icon="🍪" defaultOpen={false}><ErrorNote msg={data.error} /></SectionCard>;
  if (!data.cookies?.length) return (
    <SectionCard title="Cookies" icon="🍪" defaultOpen={false}>
      <p className="text-slate-500 text-sm">No cookies set.</p>
    </SectionCard>
  );
  return (
    <SectionCard title="Cookies" icon="🍪" defaultOpen={false}>
      <div className="space-y-2">
        {data.cookies?.map((c, i) => (
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
    </SectionCard>
  );
}

function TechStackCard({ data }: { data: TechResult }) {
  if (data.error) return <SectionCard title="Tech Stack" icon="🛠" defaultOpen={false}><ErrorNote msg={data.error} /></SectionCard>;
  if (!data.technologies?.length) return (
    <SectionCard title="Tech Stack" icon="🛠" defaultOpen={false}>
      <p className="text-slate-500 text-sm">No technologies detected.</p>
    </SectionCard>
  );
  const grouped = data.technologies?.reduce<Record<string, string[]>>((acc, t) => {
    (acc[t.category] = acc[t.category] || []).push(t.name);
    return acc;
  }, {});
  return (
    <SectionCard title="Tech Stack" icon="🛠" defaultOpen={false}>
      <div className="space-y-3">
        {Object.entries(grouped ?? {}).map(([cat, names]) => (
          <div key={cat}>
            <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{cat}</p>
            <div className="flex flex-wrap">{names.map(n => <Tag key={n}>{n}</Tag>)}</div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

// ── Main App ─────────────────────────────────────────────────────────────────

export default function App() {
  const [url, setUrl] = useState('');
  const [consent, setConsent] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<ScanResults | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleScan = async () => {
    if (!url.trim()) { setError('Please enter a URL.'); return; }
    if (!consent) { setError('You must confirm you have authorization to scan this website.'); return; }

    setScanning(true);
    setError(null);
    setResults(null);

    try {
      const resp = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url.trim(), consent }),
      });
      const data = await resp.json();
      if (!resp.ok) { setError(data.error || 'Scan failed.'); return; }
      setResults(data);
    } catch (err) {
      setError('Could not reach the scanner API. Is the server running?');
    } finally {
      setScanning(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && consent) handleScan();
  };

  return (
    <div className="min-h-screen" style={{ background: 'linear-gradient(135deg, #09090f 0%, #0f0f1e 100%)' }}>
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center gap-3">
        <span className="text-3xl">🦄</span>
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight">Unicorn Scanner</h1>
          <p className="text-xs text-slate-500">Authorized website intelligence</p>
        </div>
        <span className="ml-auto text-xs text-slate-600 bg-slate-800 px-2 py-1 rounded">v2.0</span>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-10">
        {/* Scan Form */}
        <div className="bg-slate-900 border border-slate-700 rounded-2xl p-6 mb-8 shadow-xl shadow-purple-950/20">
          <h2 className="text-slate-300 font-semibold mb-4 text-sm uppercase tracking-widest">Target URL</h2>

          <div className="flex gap-3 mb-4">
            <input
              type="text"
              placeholder="https://example.com"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={handleKey}
              disabled={scanning}
              className="flex-1 bg-slate-800 border border-slate-600 rounded-lg px-4 py-3 text-white placeholder-slate-500 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500 transition-colors font-mono disabled:opacity-50"
            />
            <button
              onClick={handleScan}
              disabled={scanning || !consent}
              className="px-6 py-3 rounded-lg font-semibold text-white transition-all disabled:opacity-40 disabled:cursor-not-allowed"
              style={{ background: scanning ? '#4c1d95' : 'linear-gradient(135deg, #7c3aed, #6d28d9)' }}
            >
              {scanning ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"/>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"/>
                  </svg>
                  Scanning…
                </span>
              ) : 'Scan'}
            </button>
          </div>

          {/* Consent checkbox */}
          <label className="flex items-start gap-3 cursor-pointer group">
            <div className="relative mt-0.5">
              <input
                type="checkbox"
                checked={consent}
                onChange={e => setConsent(e.target.checked)}
                className="sr-only"
              />
              <div className={`w-5 h-5 rounded border-2 flex items-center justify-center transition-all ${consent ? 'bg-purple-600 border-purple-600' : 'border-slate-600 bg-slate-800 group-hover:border-slate-500'}`}>
                {consent && <svg viewBox="0 0 12 10" fill="none" className="w-3 h-3"><path d="M1 5l3 3 7-7" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/></svg>}
              </div>
            </div>
            <span className="text-sm text-slate-400 leading-relaxed">
              I confirm I have <span className="text-white font-medium">explicit authorization</span> to scan this website. Unauthorized scanning may be illegal. This tool is for authorized security testing, research, and reconnaissance only.
            </span>
          </label>

          {error && (
            <div className="mt-4 p-3 bg-red-950/50 border border-red-800 rounded-lg text-red-300 text-sm">
              {error}
            </div>
          )}
        </div>

        {/* Loading state */}
        {scanning && (
          <div className="text-center py-16">
            <div className="inline-flex flex-col items-center gap-4">
              <div className="relative">
                <div className="w-16 h-16 rounded-full border-4 border-slate-700 border-t-purple-500 animate-spin"/>
                <span className="absolute inset-0 flex items-center justify-center text-2xl">🦄</span>
              </div>
              <p className="text-slate-400 animate-pulse">Running all scans in parallel…</p>
              <div className="flex gap-2 text-xs text-slate-600">
                {['Online check','SSL','DNS','WHOIS','Headers','Performance','WordPress','Cookies','Tech stack'].map(s => (
                  <span key={s} className="bg-slate-800 px-2 py-1 rounded">{s}</span>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {results && !scanning && (
          <>
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="text-sm text-slate-500">Results for</p>
                <p className="font-mono text-purple-300 font-semibold">{results.hostname}</p>
              </div>
              <p className="text-xs text-slate-600">{new Date(results.timestamp).toLocaleString()}</p>
            </div>

            {/* Top row — most important cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <OnlineCard data={results.online} />
              <SSLCard data={results.ssl} />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
              <PerformanceCard data={results.performance} />
              <TechStackCard data={results.techStack} />
            </div>

            <div className="space-y-4">
              <HeadersCard data={results.headers} />
              <DNSCard data={results.dns} />
              <WhoisCard data={results.whois} />
              <WordPressCard data={results.wordpress} />
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
