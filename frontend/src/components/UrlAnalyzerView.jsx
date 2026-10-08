import React, { useState } from 'react';
import { 
  Globe, 
  Send, 
  Terminal, 
  CheckCircle2, 
  AlertCircle, 
  ShieldAlert, 
  ShieldCheck, 
  AlertTriangle, 
  CheckSquare, 
  ChevronDown, 
  ChevronUp, 
  RefreshCw, 
  Info,
  Server,
  Layers,
  Search,
  Lock,
  ExternalLink,
  Cpu
} from 'lucide-react';
import { analyzeUrl } from '../services/api';

const PRESETS = [
  {
    label: 'Normal HTTPS URL',
    category: 'url',
    inputType: 'url',
    input: 'https://www.google.com/search?q=cybersecurity'
  },
  {
    label: 'Brand Lookalike Phish',
    category: 'url',
    inputType: 'url',
    input: 'http://paypa1-account-security-update.xyz/login/verify?token=%20%20%2e'
  },
  {
    label: 'URL with IP Host',
    category: 'url',
    inputType: 'url',
    input: 'http://192.168.1.100:8443/admin/login'
  },
  {
    label: 'Deceptive @ Userinfo',
    category: 'url',
    inputType: 'url',
    input: 'http://paypal.com@malicious-redirect-portal.net/security/update'
  },
  {
    label: 'Legitimate Domain',
    category: 'domain',
    inputType: 'domain',
    input: 'example.com'
  },
  {
    label: 'Suspicious Domain',
    category: 'domain',
    inputType: 'domain',
    input: 'login-secure-example.xyz'
  },
  {
    label: 'Punycode IDN Domain',
    category: 'domain',
    inputType: 'domain',
    input: 'xn--pple-43d.com'
  },
  {
    label: 'Public IP Address',
    category: 'ip',
    inputType: 'ip',
    input: '8.8.8.8'
  },
  {
    label: 'Internal Private IP',
    category: 'ip',
    inputType: 'ip',
    input: '192.168.1.1'
  }
];

const RISK_LEVEL_CONFIG = {
  SAFE: {
    badgeBg: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    barColor: 'bg-emerald-500',
    icon: ShieldCheck,
    textCol: 'text-emerald-400'
  },
  LOW: {
    badgeBg: 'bg-blue-500/10 border-blue-500/30 text-blue-400',
    barColor: 'bg-blue-400',
    icon: CheckCircle2,
    textCol: 'text-blue-400'
  },
  MEDIUM: {
    badgeBg: 'bg-amber-400/10 border-amber-400/30 text-amber-400',
    barColor: 'bg-amber-400',
    icon: AlertTriangle,
    textCol: 'text-amber-400'
  },
  HIGH: {
    badgeBg: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    barColor: 'bg-orange-500',
    icon: ShieldAlert,
    textCol: 'text-orange-400'
  },
  CRITICAL: {
    badgeBg: 'bg-red-500/10 border-red-500/30 text-red-400',
    barColor: 'bg-red-500',
    icon: AlertCircle,
    textCol: 'text-red-400'
  }
};

export default function UrlAnalyzerView() {
  const [selectedType, setSelectedType] = useState('auto'); // 'auto' | 'url' | 'domain' | 'ip'
  const [targetInput, setTargetInput] = useState('http://paypa1-account-security-update.xyz/login/verify?token=%20%20%2e');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showJsonInspector, setShowJsonInspector] = useState(false);

  const getPlaceholder = () => {
    switch (selectedType) {
      case 'url':
        return 'https://login.example.com/account/verify or http://192.168.1.100/portal';
      case 'domain':
        return 'example.com or login-secure-portal.xyz or xn--pple-43d.com';
      case 'ip':
        return '8.8.8.8 or 192.168.1.100 or 2001:4860:4860::8888';
      default:
        return 'Enter Full URL, Domain Name, or IP Address...';
    }
  };

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    if (!targetInput.trim()) return;

    setLoading(true);
    setError(null);
    setResult(null);

    const payload = {
      input: targetInput.trim(),
      url: targetInput.trim(),
      input_type: selectedType
    };

    const res = await analyzeUrl(payload);
    if (res.success && res.data) {
      setResult(res.data);
    } else {
      setError(res.error || 'Failed to connect to URL/Domain security analysis endpoint.');
    }
    setLoading(false);
  };

  const handleApplyPreset = (preset) => {
    setSelectedType(preset.inputType || 'auto');
    setTargetInput(preset.input);
    setResult(null);
    setError(null);
  };

  const handleClear = () => {
    setTargetInput('');
    setResult(null);
    setError(null);
  };

  const severityMeta = result ? (RISK_LEVEL_CONFIG[result.risk_level || result.severity] || RISK_LEVEL_CONFIG.MEDIUM) : RISK_LEVEL_CONFIG.SAFE;
  const SeverityIcon = severityMeta.icon;

  return (
    <div className="url-analyzer-view space-y-6 max-w-6xl mx-auto pb-8">
      {/* Header Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight flex items-center space-x-2">
            <Globe className="w-5 h-5 text-red-600" />
            <span>URL, Domain & IP Threat Analyzer</span>
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Deep heuristic inspection of URLs, domains, and IP addresses for deceptive structure, lookalikes, punycode, and credential lures.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-[11px] px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-400 font-mono">
            Passive Telemetry Engine
          </span>
        </div>
      </div>

      {/* Preset Scenarios */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex flex-wrap items-center gap-2">
        <span className="text-xs font-semibold text-slate-300 mr-1 flex items-center space-x-1.5">
          <span>Test Scenarios:</span>
        </span>
        {PRESETS.map((preset, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleApplyPreset(preset)}
            className="text-xs font-mono px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/80 transition-all cursor-pointer"
          >
            {preset.label}
          </button>
        ))}
        <button
          type="button"
          onClick={handleClear}
          className="text-xs px-2.5 py-1 rounded bg-slate-950 hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 ml-auto transition-all cursor-pointer flex items-center space-x-1"
        >
          <RefreshCw className="w-3 h-3" />
          <span>Reset</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Input Column */}
        <div className="lg:col-span-5 space-y-4">
          <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-4 shadow-sm">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
                Input Telemetry
              </h3>
              <span className="text-[10px] text-slate-400 font-mono">
                Passive Analysis Only
              </span>
            </div>

            {/* Input Type Selector Buttons */}
            <div className="space-y-1.5">
              <label className="text-[11px] text-slate-300 font-medium">
                Input Type
              </label>
              <div className="grid grid-cols-4 gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
                {[
                  { id: 'auto', label: 'Auto Detect' },
                  { id: 'url', label: 'Full URL' },
                  { id: 'domain', label: 'Domain' },
                  { id: 'ip', label: 'IP Address' }
                ].map((tab) => (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setSelectedType(tab.id)}
                    className={`py-1.5 text-[11px] font-medium rounded transition-all cursor-pointer text-center ${
                      selectedType === tab.id
                        ? 'bg-blue-600 text-white font-semibold shadow-sm'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900'
                    }`}
                  >
                    {tab.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Input Textarea */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs text-slate-300">
                  Target {selectedType === 'auto' ? 'Indicator' : selectedType === 'url' ? 'URL' : selectedType === 'domain' ? 'Domain' : 'IP Address'}
                </label>
                <span className="text-[10px] text-red-600 font-mono">Required</span>
              </div>
              <textarea
                rows={3}
                value={targetInput}
                onChange={(e) => setTargetInput(e.target.value)}
                className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all resize-none"
                placeholder={getPlaceholder()}
              />
            </div>

            <button
              type="submit"
              disabled={loading || !targetInput.trim()}
              className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs tracking-wide shadow-sm transition-all disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Evaluating Telemetry...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Analyze Target Security</span>
                </>
              )}
            </button>
          </form>

          {/* Heuristic Scope Notice */}
          <div className="p-3.5 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 leading-relaxed space-y-1.5">
            <div className="flex items-center space-x-1.5 text-slate-300 font-medium">
              <Info className="w-3.5 h-3.5 text-red-600 shrink-0" />
              <span>Passive Heuristic Boundary</span>
            </div>
            <p>
              The analyzer evaluates observable syntactic characteristics, domain structure, homoglyphs, and keyword lures. It does not perform active port scanning, DNS attacks, or payload execution.
            </p>
          </div>
        </div>

        {/* Results Column */}
        <div className="lg:col-span-7 space-y-4">
          {error && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start space-x-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Inspection Error</p>
                <p className="text-red-300 text-[11px] mt-0.5">{error}</p>
              </div>
            </div>
          )}

          {result ? (
            <div className="space-y-4">
              {/* Risk Assessment Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 shadow-sm space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <div className="space-y-0.5">
                    <div className="text-[11px] text-slate-400 uppercase font-semibold tracking-wider">
                      Classification: {result.classification || result.threat_type}
                    </div>
                    <div className="flex items-center space-x-2.5">
                      <div className={`p-2 rounded-lg ${severityMeta.badgeBg}`}>
                        <SeverityIcon className="w-5 h-5" />
                      </div>
                      <div>
                        <div className="flex items-baseline space-x-1.5">
                          <span className="text-2xl font-bold text-white font-mono">
                            {result.risk_score}
                          </span>
                          <span className="text-xs text-slate-500 font-mono">/ 100</span>
                        </div>
                        <div className="text-xs font-semibold text-slate-300">
                          Severity: <span className={severityMeta.textCol}>{result.risk_level || result.severity}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col sm:items-end space-y-1">
                    <span className={`text-xs font-mono px-2.5 py-1 rounded border font-bold uppercase ${severityMeta.badgeBg}`}>
                      {result.risk_level || result.severity}
                    </span>
                    <span className="text-[10px] text-slate-400 font-mono">
                      Type: <span className="text-slate-200 uppercase font-semibold">{result.input_type || 'URL'}</span>
                    </span>
                  </div>
                </div>

                {/* Score Progress Bar */}
                <div className="space-y-1">
                  <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${severityMeta.barColor} transition-all duration-500`}
                      style={{ width: `${Math.max(4, result.risk_score)}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] font-mono text-slate-500">
                    <span>0 (Safe)</span>
                    <span>20 (Low)</span>
                    <span>40 (Medium)</span>
                    <span>70 (High)</span>
                    <span>90 (Critical)</span>
                  </div>
                </div>

                {/* Synthesized Analysis */}
                <div className="pt-2.5 border-t border-slate-800">
                  <div className="text-xs font-semibold text-slate-300 mb-1">
                    Telemetry Synthesis & Assessment
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800">
                    {result.explanation}
                  </p>
                </div>
              </div>

              {/* Technical Domain & IP Details Grid */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {/* Domain Telemetry Card */}
                {result.domain_details && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 space-y-2">
                    <div className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5 border-b border-slate-800 pb-2">
                      <Globe className="w-3.5 h-3.5 text-blue-400" />
                      <span>Domain Breakdown</span>
                    </div>
                    <div className="space-y-1.5 text-xs">
                      <div className="flex justify-between text-slate-400">
                        <span>Registrable Domain:</span>
                        <span className="font-mono text-slate-200">{result.domain || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Subdomain:</span>
                        <span className="font-mono text-slate-200">{result.subdomain || 'None (Apex)'}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Top-Level Domain (TLD):</span>
                        <span className="font-mono text-slate-200">{result.tld || 'N/A'}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Punycode / IDN:</span>
                        <span className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${result.domain_details.is_punycode ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-slate-950 text-slate-400 border-slate-800'}`}>
                          {result.domain_details.is_punycode ? 'Detected (xn--)' : 'Standard ASCII'}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Syntax Status:</span>
                        <span className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${result.domain_details.is_valid ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                          {result.domain_details.is_valid ? 'Valid FQDN' : 'Invalid Syntax'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}

                {/* IP Telemetry Card */}
                {result.ip_details && (
                  <div className="bg-slate-900 border border-slate-800 rounded-xl p-3.5 space-y-2">
                    <div className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5 border-b border-slate-800 pb-2">
                      <Server className="w-3.5 h-3.5 text-blue-400" />
                      <span>IP Address Telemetry</span>
                    </div>
                    <div className="space-y-1.5 text-xs">
                      <div className="flex justify-between text-slate-400">
                        <span>Target IP:</span>
                        <span className="font-mono text-slate-200">{result.ip_details.ip_address || result.ip_address}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Protocol Version:</span>
                        <span className="font-mono text-slate-200">{result.ip_details.version || 'Unparsed'}</span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Address Scope:</span>
                        <span className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${result.ip_details.is_private ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' : 'bg-blue-500/10 text-blue-400 border-blue-500/30'}`}>
                          {result.ip_details.is_private ? 'Private / RFC1918' : 'Public / Globally Routable'}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Direct Host Usage:</span>
                        <span className="font-mono text-slate-300">
                          {result.ip_details.is_direct_host ? 'Yes (No Domain Name)' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Validation Status:</span>
                        <span className={`font-mono text-[11px] px-1.5 py-0.2 rounded border ${result.ip_details.is_valid ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' : 'bg-rose-500/10 text-rose-400 border-rose-500/30'}`}>
                          {result.ip_details.is_valid ? 'Valid IP' : 'Invalid Format'}
                        </span>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Threat Intelligence / Live Reputation Hook */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-3 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2 text-slate-300">
                  <Layers className="w-4 h-4 text-slate-400" />
                  <div>
                    <span className="font-medium text-white">Threat Intelligence Reputation: </span>
                    <span className="text-slate-400">{result.reputation_status || 'Not configured'}</span>
                  </div>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-400">
                  Observable Heuristics
                </span>
              </div>

              {/* Security Evidence */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Security Evidence ({result.evidence?.length || 0})</span>
                  </h4>
                </div>

                {result.evidence && result.evidence.length > 0 ? (
                  <div className="space-y-1.5">
                    {result.evidence.map((item, idx) => (
                      <div
                        key={idx}
                        className="bg-slate-950 border border-slate-800 rounded p-2.5 space-y-0.5"
                      >
                        <div className="text-xs font-semibold text-amber-300 flex items-center space-x-1.5">
                          <span>âœ“</span>
                          <span>{item.indicator}</span>
                        </div>
                        <p className="text-xs text-slate-300 pl-4">
                          {item.details}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded bg-slate-950 border border-slate-800 text-slate-400 text-xs">
                    No anomalous or deceptive patterns were detected.
                  </div>
                )}
              </div>

              {/* Recommended Response */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                  <span>Recommended Response Actions</span>
                </h4>

                <div className="space-y-1.5">
                  {(result.recommended_response || result.recommended_actions || []).map((act, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded p-2.5 text-xs text-slate-300 flex items-start space-x-2"
                    >
                      <span className="w-4 h-4 rounded bg-slate-800 text-slate-300 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span>{act}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Raw JSON Payload */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-3">
                <button
                  type="button"
                  onClick={() => setShowJsonInspector(!showJsonInspector)}
                  className="w-full flex items-center justify-between text-xs text-slate-400 hover:text-slate-200 cursor-pointer"
                >
                  <span className="flex items-center space-x-1.5">
                    <Terminal className="w-3.5 h-3.5" />
                    <span>Structured JSON Telemetry</span>
                  </span>
                  {showJsonInspector ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>

                {showJsonInspector && (
                  <div className="mt-2.5 bg-slate-950 rounded p-3 border border-slate-800 font-mono text-xs overflow-x-auto text-slate-300">
                    <pre>{JSON.stringify(result, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 flex flex-col items-center justify-center text-center min-h-[380px] space-y-3">
              <div className="w-10 h-10 rounded-lg bg-red-100 flex items-center justify-center text-red-600">
                <Globe className="w-5 h-5" />
              </div>
              <div className="max-w-xs space-y-1">
                <div className="text-xs font-semibold text-slate-200">No Target Inspection Active</div>
                <p className="text-[11px] text-slate-600">
                  Select a test scenario above or input a URL, domain, or IP address to perform passive telemetry evaluation.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


