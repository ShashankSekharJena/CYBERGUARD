import React, { useState } from 'react';
import { 
  MailWarning, 
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
  Sparkles
} from 'lucide-react';
import { analyzePhishing } from '../services/api';

const PRESETS = [
  {
    label: 'Safe Memo',
    type: 'safe',
    data: {
      message_text: 'Hi team, please find the quarterly engineering progress notes attached. Our all-hands sync is scheduled for Friday at 3 PM.',
      url: 'https://internal-wiki.company.corp/engineering/q3-summary',
      sender: 'alex.director@company.com'
    }
  },
  {
    label: 'Urgent Credential Lure',
    type: 'threat',
    data: {
      message_text: 'URGENT: Your account access has been restricted due to unauthorized activity. Please verify your password immediately to avoid termination.',
      url: 'http://login-security-check.net/verify',
      sender: 'security@untrusted-auth.net'
    }
  },
  {
    label: 'Brand Lookalike Phish',
    type: 'critical',
    data: {
      message_text: 'PayPal Security Alert: Suspicious transaction detected. Confirm your login credentials and OTP immediately to secure your funds.',
      url: 'http://paypa1-account-verification.com/signin',
      sender: 'alerts@paypa1-service.com'
    }
  },
  {
    label: 'Deceptive IP Link',
    type: 'threat',
    data: {
      message_text: 'Important notification regarding your billing account. Follow the instructions at the portal link.',
      url: 'http://192.168.1.100/admin@secure-billing-center.xyz/update',
      sender: 'billing@portal-center.xyz'
    }
  }
];

const SEVERITY_CONFIG = {
  SAFE: {
    badgeBg: 'bg-emerald-100 text-emerald-700',
    barColor: 'bg-emerald-500',
    icon: ShieldCheck,
    textCol: 'text-emerald-700'
  },
  LOW: {
    badgeBg: 'bg-blue-100 text-blue-700',
    barColor: 'bg-blue-500',
    icon: CheckCircle2,
    textCol: 'text-blue-700'
  },
  MEDIUM: {
    badgeBg: 'bg-amber-100 text-amber-700',
    barColor: 'bg-amber-500',
    icon: AlertTriangle,
    textCol: 'text-amber-700'
  },
  HIGH: {
    badgeBg: 'bg-orange-100 text-orange-700',
    barColor: 'bg-orange-500',
    icon: ShieldAlert,
    textCol: 'text-orange-700'
  },
  CRITICAL: {
    badgeBg: 'bg-red-100 text-red-700',
    barColor: 'bg-red-500',
    icon: AlertCircle,
    textCol: 'text-red-700'
  }
};

export default function PhishingAnalyzerView() {
  const [formData, setFormData] = useState({
    message_text: 'URGENT: Your PayPal account access has been restricted. Click the link immediately to verify your password and avoid suspension.',
    url: 'http://paypa1-security-verification.com/login',
    sender: 'security-alert@fakebank-portal.net',
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
      url: formData.url,
      sender: formData.sender
    };

    const res = await analyzePhishing(payload);
    if (res.success && res.data) {
      setResult(res.data);
    } else {
      setError(res.error || 'Failed to connect to phishing detection endpoint.');
    }
    setLoading(false);
  };

  const handleApplyPreset = (preset) => {
    setFormData({
      message_text: preset.data.message_text,
      url: preset.data.url,
      sender: preset.data.sender || ''
    });
    setResult(null);
    setError(null);
  };

  const handleClear = () => {
    setFormData({
      message_text: '',
      url: '',
      sender: ''
    });
    setResult(null);
    setError(null);
  };

  const severityMeta = result ? (SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.MEDIUM) : SEVERITY_CONFIG.SAFE;
  const SeverityIcon = severityMeta.icon;

  return (
    <div className="max-w-6xl mx-auto px-6 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          Phishing Threat Detection
        </h1>
        <p className="text-sm text-slate-600 mt-2">
          Evaluate suspicious email content, credential solicitation patterns, and deceptive URLs.
        </p>
      </div>

      {/* Preset Scenarios */}
      <div className="bg-white border border-slate-200 rounded-lg p-4 mb-6 flex flex-wrap items-center gap-2">
        <span className="text-sm font-medium text-slate-700 mr-2">Test Scenarios:</span>
        {PRESETS.map((preset, idx) => (
          <button
            key={idx}
            type="button"
            onClick={() => handleApplyPreset(preset)}
            className="text-sm px-3 py-1.5 rounded bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-300 transition-all cursor-pointer"
          >
            {preset.label}
          </button>
        ))}
        <button
          type="button"
          onClick={handleClear}
          className="text-sm px-3 py-1.5 rounded bg-white hover:bg-slate-50 text-slate-600 border border-slate-300 ml-auto transition-all cursor-pointer flex items-center space-x-1"
        >
          <RefreshCw className="w-4 h-4" />
          <span>Reset</span>
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
        {/* Input Form Column */}
        <div className="lg:col-span-5">
          <form onSubmit={handleSubmit} className="bg-white border border-slate-200 rounded-lg p-6 space-y-5">
            <h2 className="text-base font-semibold text-slate-900">Input Telemetry</h2>

            {/* Message Text Input */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center justify-between">
                <span>Message Body / Email Content</span>
                <span className="text-xs text-slate-500">Required</span>
              </label>
              <textarea
                rows={6}
                value={formData.message_text}
                onChange={(e) => setFormData({ ...formData, message_text: e.target.value })}
                className="w-full bg-slate-50 border border-slate-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-lg p-3 text-sm text-slate-900 placeholder-slate-400 focus:outline-none transition-all resize-none"
                placeholder="Paste message text or email body..."
              />
            </div>

            {/* URL Input */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center justify-between">
                <span>Target URL</span>
                <span className="text-xs text-slate-500">Optional</span>
              </label>
              <input
                type="text"
                value={formData.url}
                onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                className="w-full bg-slate-50 border border-slate-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none transition-all"
                placeholder="e.g. http://login-verify-service.com/signin"
              />
            </div>

            {/* Sender / Origin Input */}
            <div className="space-y-2">
              <label className="text-sm font-medium text-slate-700 flex items-center justify-between">
                <span>Sender Address / Origin</span>
                <span className="text-xs text-slate-500">Optional</span>
              </label>
              <input
                type="text"
                value={formData.sender}
                onChange={(e) => setFormData({ ...formData, sender: e.target.value })}
                className="w-full bg-slate-50 border border-slate-300 focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none transition-all"
                placeholder="e.g. alerts@company-security.net"
              />
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading || (!formData.message_text.trim() && !formData.url.trim())}
              className="w-full flex items-center justify-center space-x-2 py-3 px-4 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-semibold text-sm transition-all disabled:opacity-50 cursor-pointer"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  <span>Evaluating Threat...</span>
                </>
              ) : (
                <>
                  <Send className="w-4 h-4" />
                  <span>Analyze Threat</span>
                </>
              )}
            </button>
          </form>

          {/* Transparent Notice */}
          <div className="p-4 rounded-lg bg-slate-50 border border-slate-200 text-sm text-slate-600 leading-relaxed flex items-start space-x-2 mt-4">
            <Info className="w-5 h-5 text-slate-500 shrink-0 mt-0.5" />
            <div>
              <span className="font-medium text-slate-700">Heuristic Analysis: </span>
              Scores are computed via weighted heuristic indicator evaluation. Machine learning confidence remains unassigned until model validation is active.
            </div>
          </div>
        </div>

        {/* Results Column */}
        <div className="lg:col-span-7">
          {error && (
            <div className="p-4 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm flex items-start space-x-3 mb-6">
              <AlertCircle className="w-5 h-5 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Analysis Error</p>
                <p className="text-red-600 text-sm mt-1">{error}</p>
              </div>
            </div>
          )}

          {result ? (
            <div className="space-y-6">
              {/* Risk Assessment Card */}
              <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                  <div className="space-y-1">
                    <div className="text-sm text-slate-500 font-medium">
                      Classification: {result.threat_type}
                    </div>
                    <div className="flex items-center space-x-3">
                      <div className={`p-3 rounded-lg ${severityMeta.badgeBg}`}>
                        <SeverityIcon className="w-6 h-6" />
                      </div>
                      <div>
                        <div className="flex items-baseline space-x-2">
                          <span className="text-3xl font-bold text-slate-900 font-mono">
                            {result.risk_score}
                          </span>
                          <span className="text-sm text-slate-500 font-mono">/ 100</span>
                        </div>
                        <div className="text-sm font-medium text-slate-700">
                          Severity: <span className={severityMeta.textCol}>{result.severity}</span>
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex flex-col sm:items-end space-y-2">
                    <span className={`text-sm font-mono px-3 py-1.5 rounded font-semibold ${severityMeta.badgeBg}`}>
                      {result.severity}
                    </span>
                    <span className="text-xs text-slate-500">
                      ML Confidence: {result.confidence === null ? 'null (Heuristic)' : `${result.confidence}%`}
                    </span>
                  </div>
                </div>

                {/* Score Progress Bar */}
                <div className="space-y-2">
                  <div className="w-full h-2 bg-slate-200 rounded-full overflow-hidden">
                    <div
                      className={`h-full ${severityMeta.barColor} transition-all duration-500`}
                      style={{ width: `${Math.max(4, result.risk_score)}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-xs font-mono text-slate-500">
                    <span>0 (Safe)</span>
                    <span>40 (Medium)</span>
                    <span>70 (High)</span>
                    <span>100 (Critical)</span>
                  </div>
                </div>

                {/* Threat Analysis & Details */}
                <div className="pt-4 border-t border-slate-200">
                  <div className="text-sm font-semibold text-slate-900 mb-2">
                    Threat Analysis & Details
                  </div>
                  <p className="text-sm text-slate-700 leading-relaxed bg-slate-50 p-4 rounded border border-slate-200">
                    {result.explanation}
                  </p>
                </div>
              </div>

              {/* Security Evidence */}
              <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-base font-semibold text-slate-900 flex items-center space-x-2">
                    <AlertTriangle className="w-5 h-5 text-amber-600" />
                    <span>Security Evidence ({result.evidence?.length || 0})</span>
                  </h2>
                </div>

                {result.evidence && result.evidence.length > 0 ? (
                  <div className="space-y-3">
                    {result.evidence.map((item, idx) => (
                      <div
                        key={idx}
                        className="bg-slate-50 border border-slate-200 rounded p-4 space-y-2"
                      >
                        <div className="text-sm font-semibold text-amber-700">
                          {item.indicator}
                        </div>
                        <p className="text-sm text-slate-700">
                          {item.details}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-4 rounded bg-slate-50 border border-slate-200 text-slate-600 text-sm">
                    No threat indicators were detected in this submission.
                  </div>
                )}
              </div>

              {/* Recommended Actions */}
              <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
                <h2 className="text-base font-semibold text-slate-900 flex items-center space-x-2">
                  <CheckSquare className="w-5 h-5 text-blue-600" />
                  <span>Recommended Actions</span>
                </h2>

                <div className="space-y-2">
                  {result.recommended_actions && result.recommended_actions.map((act, idx) => (
                    <div
                      key={idx}
                      className="flex items-start space-x-2 text-sm text-slate-700"
                    >
                      <span className="text-blue-600 font-bold shrink-0">•</span>
                      <span className="leading-relaxed">{act}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="bg-white border border-slate-200 rounded-lg p-8 text-center text-slate-500">
              <MailWarning className="w-12 h-12 text-slate-300 mx-auto mb-3" />
              <div className="font-medium text-slate-700">No Analysis Results</div>
              <p className="text-sm mt-1">
                Submit message content to begin phishing threat detection.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
