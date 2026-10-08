import React, { useState } from 'react';
import { 
  UserX, 
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
  Info 
} from 'lucide-react';
import { analyzeImpersonation } from '../services/api';

const PRESETS = [
  {
    label: 'Fake Bank Support',
    type: 'threat',
    data: {
      message_text: 'Chase Customer Support: Suspicious login attempt detected on your checking account. Please verify your OTP code and password immediately to prevent lockout.',
      claimed_identity: 'Chase Bank Customer Support',
      sender: 'support@chase-security-alerts.xyz',
      url: 'http://chase-login-verify.xyz'
    }
  },
  {
    label: 'Fake Government Officer',
    type: 'critical',
    data: {
      message_text: 'IRS Tax Investigation Unit: Unpaid tax balance detected under your SSN. Submit immediate wire transfer within 2 hours or police will execute an arrest warrant.',
      claimed_identity: 'Internal Revenue Service Agent',
      sender: 'investigator-irs-department@gmail.com',
      url: ''
    }
  },
  {
    label: 'Fake Company Recruiter',
    type: 'critical',
    data: {
      message_text: 'Amazon Talent Acquisition: Congratulations on your job offer! Please purchase $500 Apple gift card for equipment onboarding and send your passport copy.',
      claimed_identity: 'Amazon HR Recruiter',
      sender: 'amazon.careers.team@yahoo.com',
      url: ''
    }
  },
  {
    label: 'Normal Professional Message',
    type: 'safe',
    data: {
      message_text: 'Hi Alex, please find the quarterly engineering summary slides attached for tomorrow\'s team architecture sync.',
      claimed_identity: 'Alex Director',
      sender: 'alex.director@company.com',
      url: ''
    }
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

export default function ImpersonationAnalyzerView() {
  const [formData, setFormData] = useState({
    message_text: 'IRS Tax Investigation Unit: Unpaid tax balance detected under your SSN. Submit immediate wire transfer within 2 hours or police will execute an arrest warrant.',
    claimed_identity: 'Internal Revenue Service Agent',
    sender: 'investigator-irs-department@gmail.com',
    url: ''
  });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [showJsonInspector, setShowJsonInspector] = useState(false);

  const handleSubmit = async (e) => {
    if (e) e.preventDefault();
    setLoading(true);
    setError(null);
    setResult(null);

    const payload = {
      message_text: formData.message_text,
      claimed_identity: formData.claimed_identity,
      sender: formData.sender,
      url: formData.url
    };

    const res = await analyzeImpersonation(payload);
    if (res.success && res.data) {
      setResult(res.data);
    } else {
      setError(res.error || 'Failed to connect to impersonation detection endpoint.');
    }
    setLoading(false);
  };

  const handleApplyPreset = (preset) => {
    setFormData({
      message_text: preset.data.message_text,
      claimed_identity: preset.data.claimed_identity,
      sender: preset.data.sender,
      url: preset.data.url
    });
    setResult(null);
    setError(null);
  };

  const handleClear = () => {
    setFormData({
      message_text: '',
      claimed_identity: '',
      sender: '',
      url: ''
    });
    setResult(null);
    setError(null);
  };

  const severityMeta = result ? (RISK_LEVEL_CONFIG[result.risk_level] || RISK_LEVEL_CONFIG.MEDIUM) : RISK_LEVEL_CONFIG.SAFE;
  const SeverityIcon = severityMeta.icon;

  return (
    <div className="space-y-6 max-w-6xl mx-auto pb-8">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-white tracking-tight">
            Digital Impersonation Detection
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Identify sender domain mismatch, executive authority spoofing, and brand imitation.
          </p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-[11px] px-2.5 py-1 rounded bg-slate-800 border border-slate-700 text-slate-400 font-mono">
            Detector
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
          <form onSubmit={handleSubmit} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3.5 shadow-sm">
            <h3 className="text-xs font-semibold text-white uppercase tracking-wider">
              Input Telemetry
            </h3>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 flex items-center justify-between">
                <span>Claimed Identity / Organization</span>
                <span className="text-[10px] text-slate-500">Required</span>
              </label>
              <input
                type="text"
                value={formData.claimed_identity}
                onChange={(e) => setFormData({ ...formData, claimed_identity: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all"
                placeholder="e.g. Chief Executive Officer, IRS Agent, PayPal Support"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 flex items-center justify-between">
                <span>Sender Address / Origin</span>
                <span className="text-[10px] text-slate-500">Required</span>
              </label>
              <input
                type="text"
                value={formData.sender}
                onChange={(e) => setFormData({ ...formData, sender: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all"
                placeholder="e.g. sender@unrelated-domain.com"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 flex items-center justify-between">
                <span>Message Content</span>
                <span className="text-[10px] text-slate-500">Required</span>
              </label>
              <textarea
                rows={4}
                value={formData.message_text}
                onChange={(e) => setFormData({ ...formData, message_text: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg p-2.5 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all resize-none"
                placeholder="Message body or communication text..."
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-slate-300 flex items-center justify-between">
                <span>Target URL (if provided)</span>
                <span className="text-[10px] text-slate-500">Optional</span>
              </label>
              <input
                type="text"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg px-2.5 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all"
                placeholder="http://example-portal.com"
              />
            </div>

            <button
              type="submit"
              disabled={loading || (!formData.claimed_identity.trim() && !formData.message_text.trim())}
              className="w-full flex items-center justify-center space-x-2 py-2.5 px-4 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs tracking-wide shadow-sm transition-all disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Evaluating Identity...</span>
                </>
              ) : (
                <>
                  <Send className="w-3.5 h-3.5" />
                  <span>Analyze Impersonation</span>
                </>
              )}
            </button>
          </form>

          <div className="p-3 rounded-lg bg-slate-900 border border-slate-800 text-[11px] text-slate-400 leading-relaxed flex items-start space-x-2">
            <Info className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
            <div>
              <span className="text-slate-300 font-medium">Domain Alignment Check: </span>
              Heuristic rules evaluate domain legitimacy against claimed organization names and freemail services.
            </div>
          </div>
        </div>

        {/* Results Column */}
        <div className="lg:col-span-7 space-y-4">
          {error && (
            <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-start space-x-2.5">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Analysis Error</p>
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
                    <div className="text-[11px] text-slate-400 uppercase font-semibold">
                      Classification: {result.threat_type}
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
                          Severity: <span className={severityMeta.textCol}>{result.risk_level}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col sm:items-end space-y-1">
                    <span className={`text-xs font-mono px-2.5 py-1 rounded border font-bold uppercase ${severityMeta.badgeBg}`}>
                      {result.risk_level}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      Identity: {result.claimed_identity || 'Not Specified'}
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
                    <span>40 (Medium)</span>
                    <span>70 (High)</span>
                    <span>100 (Critical)</span>
                  </div>
                </div>

                <div className="pt-2.5 border-t border-slate-800">
                  <div className="text-xs font-semibold text-slate-300 mb-1">
                    Threat Analysis & Details
                  </div>
                  <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800">
                    {result.explanation}
                  </p>
                </div>
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
                        <div className="text-xs font-semibold text-amber-300">
                          {item.indicator}
                        </div>
                        <p className="text-xs text-slate-300">
                          {item.details}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-3 rounded bg-slate-950 border border-slate-800 text-slate-400 text-xs">
                    No impersonation indicators detected.
                  </div>
                )}
              </div>

              {/* Recommended Actions */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-2.5">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                  <span>Recommended Actions</span>
                </h4>

                <div className="space-y-1.5">
                  {result.recommended_actions && result.recommended_actions.map((act, idx) => (
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
                    <span>Raw JSON Payload</span>
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
              <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center text-slate-400">
                <UserX className="w-5 h-5" />
              </div>
              <div className="max-w-xs space-y-1">
                <div className="text-xs font-semibold text-slate-200">No Identity Evaluation Active</div>
                <p className="text-[11px] text-slate-400">
                  Select a test scenario above or input sender claims to evaluate domain alignment.
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
