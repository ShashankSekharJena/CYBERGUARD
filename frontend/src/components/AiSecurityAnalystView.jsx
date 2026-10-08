import React, { useState, useEffect } from 'react';
import { 
  Bot, 
  Sparkles, 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle, 
  Clock, 
  Search, 
  RefreshCw, 
  X, 
  MailWarning, 
  Globe, 
  UserX, 
  Key, 
  AlertCircle, 
  Send,
  ChevronDown,
  FileText,
  Layers,
  Info
} from 'lucide-react';
import { 
  getIncidents, 
  fetchIncidentAiAnalysis, 
  askIncidentAiChat,
  fetchIncidentCorrelation,
  fetchIncidentMitre,
  fetchIncidentPlaybook
} from '../services/api';

const SEVERITY_THEMES = {
  CRITICAL: {
    badge: 'bg-red-100 text-red-700',
    bar: 'bg-red-500',
    border: 'border-red-300',
    text: 'text-red-700',
    icon: AlertCircle
  },
  HIGH: {
    badge: 'bg-orange-100 text-orange-700',
    bar: 'bg-orange-500',
    border: 'border-orange-300',
    text: 'text-orange-700',
    icon: ShieldAlert
  },
  MEDIUM: {
    badge: 'bg-amber-100 text-amber-700',
    bar: 'bg-amber-500',
    border: 'border-amber-300',
    text: 'text-amber-700',
    icon: AlertTriangle
  },
  LOW: {
    badge: 'bg-blue-100 text-blue-700',
    bar: 'bg-blue-500',
    border: 'border-blue-300',
    text: 'text-blue-700',
    icon: CheckCircle
  },
  SAFE: {
    badge: 'bg-emerald-100 text-emerald-700',
    bar: 'bg-emerald-500',
    border: 'border-emerald-300',
    text: 'text-emerald-700',
    icon: ShieldCheck
  }
};

const THREAT_ICONS = {
  'Phishing': MailWarning,
  'URL Threat': Globe,
  'Digital Impersonation': UserX,
  'Account Security': Key
};

export default function AiSecurityAnalystView() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [loadingIncidents, setLoadingIncidents] = useState(false);
  const [incidentsError, setIncidentsError] = useState(null);
  const [showIncidentDropdown, setShowIncidentDropdown] = useState(false);

  // AI Analysis state
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);

  // AI Chat state
  const [chatInput, setChatInput] = useState('');
  const [chatHistory, setChatHistory] = useState([]);
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState(null);

  // Additional incident context
  const [correlationData, setCorrelationData] = useState(null);
  const [mitreData, setMitreData] = useState(null);
  const [playbookData, setPlaybookData] = useState(null);
  const [loadingContext, setLoadingContext] = useState(false);

  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const fetchIncidents = async () => {
    setLoadingIncidents(true);
    setIncidentsError(null);
    try {
      const res = await getIncidents({ sort_by: 'timestamp', order: 'desc' });
      if (res.success && res.data) {
        setIncidents(res.data.incidents || []);
      } else {
        setIncidentsError(res.error || 'Failed to load incidents.');
      }
    } catch (err) {
      setIncidentsError(err.message || 'An error occurred while fetching incidents.');
    } finally {
      setLoadingIncidents(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleSelectIncident = async (incident) => {
    setSelectedIncident(incident);
    setShowIncidentDropdown(false);
    setAiAnalysis(null);
    setChatHistory([]);
    setAiError(null);
    setChatError(null);
    setCorrelationData(null);
    setMitreData(null);
    setPlaybookData(null);

    // Load additional context
    if (incident) {
      setLoadingContext(true);
      try {
        const [corrRes, mitreRes, playbookRes] = await Promise.all([
          fetchIncidentCorrelation(incident.incident_id),
          fetchIncidentMitre(incident.incident_id),
          fetchIncidentPlaybook(incident.incident_id)
        ]);
        if (corrRes.success) setCorrelationData(corrRes.data);
        if (mitreRes.success) setMitreData(mitreRes.data);
        if (playbookRes.success) setPlaybookData(playbookRes.data);
      } catch (err) {
        console.error('Failed to load incident context:', err);
      } finally {
        setLoadingContext(false);
      }
    }
  };

  const handleGenerateAiAnalysis = async () => {
    if (!selectedIncident) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await fetchIncidentAiAnalysis(selectedIncident.incident_id);
      if (res.success && res.data) {
        setAiAnalysis(res.data);
        showToast(
          res.data.is_fallback
            ? 'AI Analysis generated (Fallback Mode)'
            : 'AI Analysis generated (AI Live)'
        );
      } else {
        setAiError(res.error || 'Failed to generate AI analysis.');
      }
    } catch (err) {
      setAiError(err.message || 'An error occurred while generating analysis.');
    } finally {
      setAiLoading(false);
    }
  };

  const handleAskAiQuestion = async (queryText = null) => {
    if (!selectedIncident) return;
    const question = (queryText !== null ? queryText : chatInput).trim();
    if (!question) return;
    if (queryText === null) {
      setChatInput('');
    }
    setChatLoading(true);
    setChatError(null);
    try {
      const res = await askIncidentAiChat(selectedIncident.incident_id, question);
      if (res.success && res.data) {
        setChatHistory((prev) => [
          ...prev,
          {
            question,
            answer: res.data.answer,
            status: res.data.status,
            is_fallback: res.data.is_fallback
          }
        ]);
      } else {
        setChatError(res.error || 'Failed to retrieve answer from AI analyst.');
      }
    } catch (err) {
      setChatError(err.message || 'An error occurred during AI chat.');
    } finally {
      setChatLoading(false);
    }
  };

  const formatTimestamp = (isoString) => {
    if (!isoString) return 'Just now';
    try {
      const date = new Date(isoString);
      return date.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false
      });
    } catch {
      return isoString;
    }
  };

  const isAvailable = aiAnalysis && !aiAnalysis.is_fallback && aiAnalysis.status === 'ai';
  const isFallback = aiAnalysis && (aiAnalysis.is_fallback || aiAnalysis.status === 'fallback');

  return (
    <div className="max-w-7xl mx-auto px-6 py-8">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-white border border-slate-200 text-slate-700 text-sm px-4 py-3 rounded-lg shadow-lg flex items-center space-x-2">
          <CheckCircle className="w-5 h-5 text-emerald-600 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
          AI Security Analyst
        </h1>
        <p className="text-sm text-slate-600 mt-2">
          Evidence-grounded threat investigation assistant
        </p>
      </div>

      {/* Incident Selector */}
      <div className="bg-white border border-slate-200 rounded-lg p-6 mb-6">
        <div className="mb-4">
          <label className="text-sm font-medium text-slate-700 block mb-2">
            Select Incident
          </label>
          <p className="text-sm text-slate-500">
            Choose an incident to begin evidence-grounded analysis
          </p>
        </div>

        <div className="relative">
          <button
            type="button"
            onClick={() => setShowIncidentDropdown(!showIncidentDropdown)}
            disabled={loadingIncidents || incidents.length === 0}
            className="w-full bg-white border border-slate-300 rounded-lg px-4 py-3 text-left text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all flex items-center justify-between cursor-pointer disabled:opacity-50"
          >
            {selectedIncident ? (
              <div className="flex items-center space-x-3">
                <span className="font-mono font-semibold text-slate-900">{selectedIncident.incident_id}</span>
                <span className="text-slate-400">•</span>
                <span className="text-slate-700">{selectedIncident.classification}</span>
                <span className="text-slate-400">•</span>
                <span className={`font-semibold ${SEVERITY_THEMES[selectedIncident.risk_level]?.text || 'text-slate-600'}`}>
                  {selectedIncident.risk_level}
                </span>
              </div>
            ) : (
              <span className="text-slate-500">
                {loadingIncidents ? 'Loading incidents...' : 'Select an incident'}
              </span>
            )}
            <ChevronDown className={`w-5 h-5 text-slate-400 transition-transform ${showIncidentDropdown ? 'rotate-180' : ''}`} />
          </button>

          {showIncidentDropdown && incidents.length > 0 && (
            <div className="absolute z-10 w-full mt-1 bg-white border border-slate-300 rounded-lg shadow-lg max-h-80 overflow-y-auto">
              {incidents.map((incident) => {
                const threatIcon = THREAT_ICONS[incident.threat_type] || AlertTriangle;
                const ThreatIconComp = threatIcon;
                const severityMeta = SEVERITY_THEMES[incident.risk_level] || SEVERITY_THEMES.MEDIUM;
                return (
                  <button
                    key={incident.incident_id}
                    type="button"
                    onClick={() => handleSelectIncident(incident)}
                    className="w-full px-4 py-3 text-left hover:bg-slate-50 transition-all border-b border-slate-200 last:border-b-0"
                  >
                    <div className="flex items-center space-x-3">
                      <span className="font-mono font-semibold text-slate-900">{incident.incident_id}</span>
                      <div className="flex items-center space-x-1.5 text-sm text-slate-600">
                        <ThreatIconComp className="w-4 h-4" />
                        <span>{incident.threat_type}</span>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs font-semibold ${severityMeta.badge}`}>
                        {incident.risk_level}
                      </span>
                    </div>
                    <div className="text-sm text-slate-700 mt-1 truncate">{incident.classification}</div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        {incidentsError && (
          <div className="p-3 rounded bg-red-50 border border-red-200 text-red-700 text-sm flex items-center justify-between mt-4">
            <div className="flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{incidentsError}</span>
            </div>
            <button
              onClick={fetchIncidents}
              className="underline text-sm font-semibold hover:text-red-800 cursor-pointer"
            >
              Retry
            </button>
          </div>
        )}
      </div>

      {/* Empty State */}
      {!selectedIncident && (
        <div className="bg-white border border-slate-200 rounded-lg p-12 text-center space-y-4">
          <div className="w-16 h-16 rounded-lg bg-slate-100 mx-auto flex items-center justify-center text-slate-400">
            <Bot className="w-8 h-8" />
          </div>
          <div className="text-base font-semibold text-slate-900">AI Security Analyst</div>
          <p className="text-sm text-slate-600 max-w-sm mx-auto">
            Select an incident to begin evidence-grounded threat investigation and analysis.
          </p>
        </div>
      )}

      {/* Incident Context & AI Analysis */}
      {selectedIncident && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column: Incident Context */}
          <div className="lg:col-span-1 space-y-6">
            {/* Incident Summary Card */}
            <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
              <div className="flex items-center space-x-2 text-sm font-semibold text-slate-900">
                <FileText className="w-5 h-5 text-blue-600" />
                <span>Incident Context</span>
              </div>

              <div className="space-y-3">
                <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                  <div className="text-xs uppercase text-slate-500">Incident ID</div>
                  <div className="text-sm font-mono text-slate-900">{selectedIncident.incident_id}</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                  <div className="text-xs uppercase text-slate-500">Threat Type</div>
                  <div className="text-sm text-slate-900">{selectedIncident.threat_type}</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                  <div className="text-xs uppercase text-slate-500">Classification</div>
                  <div className="text-sm text-slate-900">{selectedIncident.classification}</div>
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                    <div className="text-xs uppercase text-slate-500">Risk Score</div>
                    <div className="text-base font-mono font-bold text-slate-900">
                      {selectedIncident.risk_score}
                      <span className="text-xs text-slate-500 font-normal">/100</span>
                    </div>
                  </div>
                  <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                    <div className="text-xs uppercase text-slate-500">Risk Level</div>
                    <div className={`text-sm font-semibold ${SEVERITY_THEMES[selectedIncident.risk_level]?.text || 'text-slate-600'}`}>
                      {selectedIncident.risk_level}
                    </div>
                  </div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                  <div className="text-xs uppercase text-slate-500">Status</div>
                  <div className="text-sm text-slate-900">{selectedIncident.status}</div>
                </div>

                <div className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                  <div className="text-xs uppercase text-slate-500">Timestamp</div>
                  <div className="text-sm text-slate-900">{formatTimestamp(selectedIncident.timestamp)}</div>
                </div>
              </div>
            </div>

            {/* Evidence Summary */}
            {selectedIncident.evidence && selectedIncident.evidence.length > 0 && (
              <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-2 text-sm font-semibold text-slate-900">
                    <AlertTriangle className="w-5 h-5 text-amber-600" />
                    <span>Evidence ({selectedIncident.evidence.length})</span>
                  </div>
                </div>

                <div className="space-y-2 max-h-60 overflow-y-auto">
                  {selectedIncident.evidence.slice(0, 5).map((ev, idx) => (
                    <div key={idx} className="bg-slate-50 border border-slate-200 rounded p-3 space-y-1">
                      <div className="text-sm font-semibold text-amber-700">{ev.indicator}</div>
                      <p className="text-sm text-slate-700 line-clamp-2">{ev.details}</p>
                    </div>
                  ))}
                  {selectedIncident.evidence.length > 5 && (
                    <div className="text-xs text-slate-500 text-center pt-2">
                      +{selectedIncident.evidence.length - 5} more indicators
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

          {/* Right Column: AI Analysis */}
          <div className="lg:col-span-2 space-y-6">
            {/* AI Analysis Panel */}
            <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-6">
              {/* Panel Header */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
                <div className="flex items-center space-x-3">
                  <div className="p-2 rounded-lg bg-blue-100 text-blue-600">
                    <Bot className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <h2 className="text-base font-bold text-slate-900">
                        AI Analysis
                      </h2>
                      {/* Status Badge */}
                      {isAvailable ? (
                        <span className="px-2 py-1 rounded text-xs font-semibold bg-emerald-100 text-emerald-700">
                          AI AVAILABLE
                        </span>
                      ) : isFallback ? (
                        <span className="px-2 py-1 rounded text-xs font-semibold bg-amber-100 text-amber-700">
                          FALLBACK MODE
                        </span>
                      ) : (
                        <span className="px-2 py-1 rounded text-xs font-medium bg-slate-100 text-slate-600">
                          READY
                        </span>
                      )}
                    </div>
                    <p className="text-sm text-slate-600">
                      Evidence-grounded threat interpretation and investigation guidance
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  disabled={aiLoading}
                  onClick={handleGenerateAiAnalysis}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold flex items-center justify-center space-x-2 transition-all disabled:opacity-50 cursor-pointer"
                >
                  {aiLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      <span>Analyzing...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-4 h-4" />
                      <span>{aiAnalysis ? 'Regenerate Analysis' : 'Generate AI Analysis'}</span>
                    </>
                  )}
                </button>
              </div>

              {/* AI Error */}
              {aiError && (
                <div className="p-3 rounded bg-red-50 border border-red-200 text-red-700 text-sm flex items-center justify-between">
                  <span>{aiError}</span>
                  <button
                    type="button"
                    onClick={handleGenerateAiAnalysis}
                    className="underline text-sm font-semibold hover:text-red-800 cursor-pointer"
                  >
                    Retry
                  </button>
                </div>
              )}

              {/* AI Analysis Content */}
              {aiAnalysis && (
                <div className="space-y-6">
                  {/* Threat Summary */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-900">
                      Threat Summary
                    </div>
                    <p className="text-sm text-slate-700 leading-relaxed bg-slate-50 p-4 rounded border border-slate-200">
                      {aiAnalysis.summary}
                    </p>
                  </div>

                  {/* Why It Matters */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-900">
                      Why It Matters
                    </div>
                    <p className="text-sm text-slate-700 leading-relaxed bg-slate-50 p-4 rounded border border-slate-200">
                      {aiAnalysis.why_it_matters}
                    </p>
                  </div>

                  {/* Key Evidence */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-900">
                      Key Evidence
                    </div>
                    <div className="bg-slate-50 p-4 rounded border border-slate-200 space-y-2">
                      {aiAnalysis.key_evidence?.map((item, idx) => (
                        <div key={idx} className="flex items-start space-x-2 text-sm text-slate-700">
                          <span className="text-blue-600 font-bold shrink-0">•</span>
                          <span className="leading-relaxed">{item}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Investigation Steps */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-900">
                      Investigation Steps
                    </div>
                    <div className="bg-slate-50 p-4 rounded border border-slate-200 space-y-2">
                      {aiAnalysis.investigation_steps?.map((step, idx) => (
                        <div key={idx} className="flex items-start space-x-3 text-sm text-slate-700">
                          <span className="w-5 h-5 rounded bg-blue-100 text-blue-700 border border-blue-200 text-xs font-mono font-bold flex items-center justify-center shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span className="leading-relaxed">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Recommended Actions */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-900">
                      Recommended Actions
                    </div>
                    <div className="bg-slate-50 p-4 rounded border border-slate-200 space-y-2">
                      {aiAnalysis.recommended_actions?.map((act, idx) => (
                        <div key={idx} className="flex items-start space-x-2 text-sm text-slate-700">
                          <span className="text-emerald-600 font-bold shrink-0">•</span>
                          <span className="leading-relaxed">{act}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Limitations */}
                  <div className="space-y-2">
                    <div className="text-sm font-semibold text-slate-600">
                      Limitations
                    </div>
                    <p className="text-sm text-slate-600 leading-relaxed bg-slate-50 p-4 rounded border border-slate-200 italic">
                      {aiAnalysis.limitations}
                    </p>
                  </div>
                </div>
              )}
            </div>

            {/* AI Chat Panel */}
            <div className="bg-white border border-slate-200 rounded-lg p-6 space-y-6">
              <div className="space-y-2">
                  <div className="text-sm font-semibold text-slate-900 uppercase">
                  Ask the Security Analyst
                </div>
                <p className="text-sm text-slate-600">
                  Evidence-grounded query answering scoped strictly to this incident's telemetry
                </p>
              </div>

              {/* Suggested Questions */}
              <div className="space-y-2">
                <div className="text-xs text-slate-500 uppercase font-medium">Suggested questions:</div>
                <div className="flex flex-wrap gap-2">
                  {[
                    'Why is this incident risky?',
                    'What evidence supports this classification?',
                    'What should I investigate first?',
                    'Are there related incidents?',
                    'What information is missing?'
                  ].map((sq, sqIdx) => (
                    <button
                      key={sqIdx}
                      type="button"
                      disabled={chatLoading}
                      onClick={() => handleAskAiQuestion(sq)}
                      className="text-sm px-3 py-1.5 rounded-full bg-slate-100 hover:bg-slate-200 border border-slate-300 text-slate-700 hover:text-slate-900 transition-all cursor-pointer text-left"
                    >
                      {sq}
                    </button>
                  ))}
                </div>
              </div>

              {/* Input Box */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  handleAskAiQuestion();
                }}
                className="flex items-center space-x-3"
              >
                <input
                  type="text"
                  value={chatInput}
                  onChange={(e) => setChatInput(e.target.value)}
                  placeholder="Ask a question about this incident..."
                  disabled={chatLoading}
                  className="flex-1 bg-slate-50 border border-slate-300 rounded-lg px-4 py-2.5 text-sm text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition-all"
                />
                <button
                  type="submit"
                  disabled={chatLoading || !chatInput.trim()}
                  className="px-4 py-2.5 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:bg-slate-200 text-white disabled:text-slate-500 text-sm font-semibold flex items-center space-x-2 transition-all cursor-pointer disabled:cursor-not-allowed shrink-0"
                >
                  {chatLoading ? (
                    <RefreshCw className="w-4 h-4 animate-spin" />
                  ) : (
                    <>
                      <span>Ask Analyst</span>
                      <Send className="w-4 h-4" />
                    </>
                  )}
                </button>
              </form>

              {/* Chat Error */}
              {chatError && (
                <div className="p-3 rounded bg-red-50 border border-red-200 text-red-700 text-sm">
                  {chatError}
                </div>
              )}

              {/* Chat History */}
              {chatHistory.length > 0 && (
                <div className="space-y-4">
                  {chatHistory.map((item, cIdx) => (
                    <div key={cIdx} className="bg-slate-50 rounded-lg p-4 border border-slate-200 space-y-3 text-sm">
                      <div className="flex items-start space-x-2 text-slate-700">
                        <span className="font-semibold text-blue-600 shrink-0">Q:</span>
                        <span className="font-medium text-slate-900">{item.question}</span>
                      </div>
                      <div className="flex items-start space-x-2 text-slate-700 pt-3 border-t border-slate-200">
                        <span className="font-semibold text-emerald-600 shrink-0">A:</span>
                        <div className="space-y-2 flex-1">
                          <p className="leading-relaxed text-slate-700 whitespace-pre-line">
                            {item.answer}
                          </p>
                          <div className="text-xs text-slate-500 font-mono">
                            {item.status === 'ai' && !item.is_fallback
                              ? 'AI AVAILABLE'
                              : 'FALLBACK MODE'}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
