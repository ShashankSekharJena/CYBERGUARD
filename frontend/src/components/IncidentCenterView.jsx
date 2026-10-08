import React, { useState, useEffect, useMemo } from 'react';
import { 
  AlertTriangle, 
  ShieldAlert, 
  ShieldCheck, 
  CheckCircle, 
  Clock, 
  Search, 
  Filter, 
  RefreshCw, 
  ChevronRight, 
  X, 
  MailWarning, 
  Globe, 
  UserX, 
  Key, 
  AlertCircle, 
  CheckSquare, 
  Terminal, 
  Copy, 
  Check, 
  ArrowUpDown, 
  Info, 
  ChevronDown, 
  ChevronUp, 
  FileText, 
  Activity, 
  Layers,
  Sparkles,
  Bot,
  Send,
  HelpCircle,
  MessageSquare
} from 'lucide-react';
import { 
  getIncidents, 
  updateIncidentStatus, 
  fetchIncidentAiAnalysis, 
  askIncidentAiChat 
} from '../services/api';

const SEVERITY_THEMES = {
  CRITICAL: {
    badge: 'bg-red-500/10 border-red-500/30 text-red-400',
    bar: 'bg-red-500',
    border: 'border-red-500/40',
    text: 'text-red-400',
    icon: AlertCircle
  },
  HIGH: {
    badge: 'bg-orange-500/10 border-orange-500/30 text-orange-400',
    bar: 'bg-orange-500',
    border: 'border-orange-500/40',
    text: 'text-orange-400',
    icon: ShieldAlert
  },
  MEDIUM: {
    badge: 'bg-amber-400/10 border-amber-400/30 text-amber-400',
    bar: 'bg-amber-400',
    border: 'border-amber-400/40',
    text: 'text-amber-400',
    icon: AlertTriangle
  },
  LOW: {
    badge: 'bg-blue-400/10 border-blue-400/30 text-blue-400',
    bar: 'bg-blue-400',
    border: 'border-blue-400/40',
    text: 'text-blue-400',
    icon: CheckCircle
  },
  SAFE: {
    badge: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    bar: 'bg-emerald-500',
    border: 'border-emerald-500/40',
    text: 'text-emerald-400',
    icon: ShieldCheck
  }
};

const STATUS_CONFIG = {
  NEW: {
    label: 'NEW',
    color: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
    dot: 'bg-blue-400'
  },
  INVESTIGATING: {
    label: 'INVESTIGATING',
    color: 'bg-amber-400/10 border-amber-400/30 text-amber-300',
    dot: 'bg-amber-400'
  },
  RESOLVED: {
    label: 'RESOLVED',
    color: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
    dot: 'bg-emerald-400'
  },
  FALSE_POSITIVE: {
    label: 'FALSE POSITIVE',
    color: 'bg-slate-700/30 border-slate-600/30 text-slate-400',
    dot: 'bg-slate-400'
  }
};

const THREAT_ICONS = {
  'Phishing': MailWarning,
  'URL Threat': Globe,
  'Digital Impersonation': UserX,
  'Account Security': Key
};

const SIGNAL_LABELS = {
  same_exact_url: 'Exact URL Match',
  same_domain: 'Same Domain / Host',
  same_sender: 'Same Sender Origin',
  same_threat_type: 'Same Threat Category',
  same_ip: 'Same IP Address',
  same_user: 'Same User Account',
  shared_indicators: 'Shared Evidence Indicators',
  recent_occurrence: 'Recent Activity (24h Window)',
};

export default function IncidentCenterView({ onTestConnection }) {
  const [incidents, setIncidents] = useState([]);
  const [metrics, setMetrics] = useState({
    total: 0,
    critical_count: 0,
    high_count: 0,
    medium_count: 0,
    low_count: 0,
    safe_count: 0,
    resolved_count: 0,
    new_count: 0,
    investigating_count: 0,
    false_positive_count: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Filters & Sorting
  const [searchQuery, setSearchQuery] = useState('');
  const [threatTypeFilter, setThreatTypeFilter] = useState('ALL');
  const [riskLevelFilter, setRiskLevelFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('timestamp');
  const [sortOrder, setSortOrder] = useState('desc');

  // Selected incident for detail view
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [updatingStatus, setUpdatingStatus] = useState(false);
  const [copiedId, setCopiedId] = useState(null);
  const [showJsonInspector, setShowJsonInspector] = useState(false);
  const [toastMessage, setToastMessage] = useState(null);

  // AI Security Analyst state
  const [aiAnalysisMap, setAiAnalysisMap] = useState({});
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState(null);
  const [chatInput, setChatInput] = useState('');
  const [chatHistoryMap, setChatHistoryMap] = useState({});
  const [chatLoading, setChatLoading] = useState(false);
  const [chatError, setChatError] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const fetchIncidents = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getIncidents({
        threat_type: threatTypeFilter !== 'ALL' ? threatTypeFilter : undefined,
        risk_level: riskLevelFilter !== 'ALL' ? riskLevelFilter : undefined,
        status: statusFilter !== 'ALL' ? statusFilter : undefined,
        search: searchQuery.trim() || undefined,
        sort_by: sortBy,
        order: sortOrder
      });

      if (res.success && res.data) {
        setIncidents(res.data.incidents || []);
        setMetrics({
          total: res.data.total || 0,
          critical_count: res.data.critical_count || 0,
          high_count: res.data.high_count || 0,
          medium_count: res.data.medium_count || 0,
          low_count: res.data.low_count || 0,
          safe_count: res.data.safe_count || 0,
          resolved_count: res.data.resolved_count || 0,
          new_count: res.data.new_count || 0,
          investigating_count: res.data.investigating_count || 0,
          false_positive_count: res.data.false_positive_count || 0,
        });

        if (selectedIncident) {
          const updatedSelected = (res.data.incidents || []).find(
            (i) => i.incident_id === selectedIncident.incident_id
          );
          if (updatedSelected) {
            setSelectedIncident(updatedSelected);
          }
        }
      } else {
        setError(res.error || 'Failed to load security incidents.');
      }
    } catch (err) {
      setError(err.message || 'An unexpected error occurred while fetching incidents.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, [threatTypeFilter, riskLevelFilter, statusFilter, sortBy, sortOrder]);

  useEffect(() => {
    const timer = setTimeout(() => {
      fetchIncidents();
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const handleUpdateStatus = async (incidentId, newStatus) => {
    setUpdatingStatus(true);
    try {
      const res = await updateIncidentStatus(incidentId, newStatus);
      if (res.success && res.data) {
        setIncidents((prev) =>
          prev.map((inc) => (inc.incident_id === incidentId ? res.data : inc))
        );
        if (selectedIncident && selectedIncident.incident_id === incidentId) {
          setSelectedIncident(res.data);
        }
        showToast(`Incident status updated to ${newStatus}`);
        fetchIncidents();
      } else {
        showToast(`Failed to update status: ${res.error || 'Server error'}`);
      }
    } catch (err) {
      showToast(`Error updating status: ${err.message}`);
    } finally {
      setUpdatingStatus(false);
    }
  };

  const handleCopyId = (id, e) => {
    if (e) e.stopPropagation();
    navigator.clipboard.writeText(id);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
    showToast(`Copied ${id} to clipboard`);
  };

  const handleResetFilters = () => {
    setSearchQuery('');
    setThreatTypeFilter('ALL');
    setRiskLevelFilter('ALL');
    setStatusFilter('ALL');
    setSortBy('timestamp');
    setSortOrder('desc');
  };

  const handleGenerateAiAnalysis = async (incidentId) => {
    if (!incidentId) return;
    setAiLoading(true);
    setAiError(null);
    try {
      const res = await fetchIncidentAiAnalysis(incidentId);
      if (res.success && res.data) {
        setAiAnalysisMap((prev) => ({
          ...prev,
          [incidentId]: res.data
        }));
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

  const handleAskAiQuestion = async (incidentId, queryText = null) => {
    if (!incidentId) return;
    const question = (queryText !== null ? queryText : chatInput).trim();
    if (!question) return;
    if (queryText === null) {
      setChatInput('');
    }
    setChatLoading(true);
    setChatError(null);
    try {
      const res = await askIncidentAiChat(incidentId, question);
      if (res.success && res.data) {
        setChatHistoryMap((prev) => ({
          ...prev,
          [incidentId]: [
            ...(prev[incidentId] || []),
            {
              question,
              answer: res.data.answer,
              status: res.data.status,
              is_fallback: res.data.is_fallback
            }
          ]
        }));
      } else {
        setChatError(res.error || 'Failed to retrieve answer from AI analyst.');
      }
    } catch (err) {
      setChatError(err.message || 'An error occurred during AI chat.');
    } finally {
      setChatLoading(false);
    }
  };

  const hasActiveFilters = 
    searchQuery.trim() !== '' ||
    threatTypeFilter !== 'ALL' ||
    riskLevelFilter !== 'ALL' ||
    statusFilter !== 'ALL' ||
    sortBy !== 'timestamp' ||
    sortOrder !== 'desc';

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

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-8">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-slate-800 border border-slate-700 text-slate-200 text-xs font-mono px-4 py-2.5 rounded-lg shadow-xl flex items-center space-x-2 animate-fade-in">
          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="space-y-0.5">
          <div className="flex items-center space-x-2">
            <h2 className="text-xl font-bold text-white tracking-tight">
              Security Incident Center
            </h2>
            <span className="text-[11px] px-2 py-0.2 rounded bg-slate-800 border border-slate-700 text-slate-400 font-mono">
              Registry
            </span>
          </div>
          <p className="text-xs text-slate-400">
            Triage, investigate, and resolve security events across all detection vectors.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            id="btn-refresh-incidents"
            onClick={fetchIncidents}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700 text-xs transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
          </button>
        </div>
      </div>

      {/* Metrics Summary Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {/* Total Incidents */}
        <div 
          onClick={() => { setRiskLevelFilter('ALL'); setStatusFilter('ALL'); }}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-slate-700 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-slate-400">Total Incidents</div>
          <div className="text-xl font-bold text-white font-mono my-0.5">{metrics.total}</div>
          <div className="text-[10px] text-slate-400">All events</div>
        </div>

        {/* Critical */}
        <div 
          onClick={() => setRiskLevelFilter('CRITICAL')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-red-500/50 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-red-400 font-medium">Critical</div>
          <div className="text-xl font-bold text-red-400 font-mono my-0.5">{metrics.critical_count}</div>
          <div className="text-[10px] text-slate-400">Score 80–100</div>
        </div>

        {/* High Risk */}
        <div 
          onClick={() => setRiskLevelFilter('HIGH')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-orange-500/50 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-orange-400 font-medium">High Risk</div>
          <div className="text-xl font-bold text-orange-400 font-mono my-0.5">{metrics.high_count}</div>
          <div className="text-[10px] text-slate-400">Score 70–79</div>
        </div>

        {/* Medium Risk */}
        <div 
          onClick={() => setRiskLevelFilter('MEDIUM')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-amber-500/50 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-amber-400 font-medium">Medium Risk</div>
          <div className="text-xl font-bold text-amber-400 font-mono my-0.5">{metrics.medium_count}</div>
          <div className="text-[10px] text-slate-400">Score 40–69</div>
        </div>

        {/* Low / Safe */}
        <div 
          onClick={() => setRiskLevelFilter('LOW')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-blue-500/50 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-blue-400 font-medium">Low / Safe</div>
          <div className="text-xl font-bold text-blue-400 font-mono my-0.5">{metrics.low_count + metrics.safe_count}</div>
          <div className="text-[10px] text-slate-400">Score &lt; 40</div>
        </div>

        {/* Resolved */}
        <div 
          onClick={() => setStatusFilter('RESOLVED')}
          className="bg-slate-900 border border-slate-800 rounded-lg p-3 hover:border-emerald-500/50 cursor-pointer transition-all"
        >
          <div className="text-[11px] text-emerald-400 font-medium">Resolved</div>
          <div className="text-xl font-bold text-emerald-400 font-mono my-0.5">{metrics.resolved_count}</div>
          <div className="text-[10px] text-slate-400">Closed</div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-2.5">
        <div className="flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-2.5">
          {/* Search Input */}
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search by ID, keyword, sender, URL, username, or evidence..."
              className="w-full bg-slate-950 border border-slate-800 focus:border-slate-700 rounded-lg pl-9 pr-8 py-2 text-xs font-mono text-slate-200 placeholder-slate-500 focus:outline-none transition-all"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 p-0.5 cursor-pointer"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Sort Selector */}
          <div className="flex items-center space-x-2 shrink-0 text-xs">
            <div className="flex items-center space-x-1.5 text-slate-400 bg-slate-950 border border-slate-800 rounded-lg px-2.5 py-1.5">
              <ArrowUpDown className="w-3.5 h-3.5 text-slate-400" />
              <select
                value={sortBy}
                onChange={(e) => setSortBy(e.target.value)}
                className="bg-transparent text-slate-200 focus:outline-none cursor-pointer text-xs"
              >
                <option value="timestamp" className="bg-slate-900 text-slate-200">Sort by: Timestamp</option>
                <option value="risk_score" className="bg-slate-900 text-slate-200">Sort by: Risk Score</option>
                <option value="incident_id" className="bg-slate-900 text-slate-200">Sort by: Incident ID</option>
              </select>
            </div>

            <button
              type="button"
              onClick={() => setSortOrder(sortOrder === 'desc' ? 'asc' : 'desc')}
              className="px-2.5 py-1.5 rounded-lg bg-slate-950 hover:bg-slate-800 border border-slate-800 text-xs font-mono text-slate-300 transition-all cursor-pointer"
            >
              {sortOrder.toUpperCase()}
            </button>
          </div>
        </div>

        {/* Filter Selectors */}
        <div className="pt-2 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2 text-xs">
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center space-x-1.5">
              <span className="text-slate-400 text-[11px]">Type:</span>
              <select
                value={threatTypeFilter}
                onChange={(e) => setThreatTypeFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs cursor-pointer focus:outline-none focus:border-slate-700"
              >
                <option value="ALL" className="bg-slate-900">All Types</option>
                <option value="Phishing" className="bg-slate-900">Phishing</option>
                <option value="URL Threat" className="bg-slate-900">URL Threat</option>
                <option value="Digital Impersonation" className="bg-slate-900">Digital Impersonation</option>
                <option value="Account Security" className="bg-slate-900">Account Security</option>
              </select>
            </div>

            <div className="flex items-center space-x-1.5">
              <span className="text-slate-400 text-[11px]">Risk:</span>
              <select
                value={riskLevelFilter}
                onChange={(e) => setRiskLevelFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs cursor-pointer focus:outline-none focus:border-slate-700"
              >
                <option value="ALL" className="bg-slate-900">All Levels</option>
                <option value="CRITICAL" className="bg-slate-900">Critical</option>
                <option value="HIGH" className="bg-slate-900">High</option>
                <option value="MEDIUM" className="bg-slate-900">Medium</option>
                <option value="LOW" className="bg-slate-900">Low</option>
                <option value="SAFE" className="bg-slate-900">Safe</option>
              </select>
            </div>

            <div className="flex items-center space-x-1.5">
              <span className="text-slate-400 text-[11px]">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded px-2 py-1 text-slate-300 text-xs cursor-pointer focus:outline-none focus:border-slate-700"
              >
                <option value="ALL" className="bg-slate-900">All Statuses</option>
                <option value="NEW" className="bg-slate-900">NEW</option>
                <option value="INVESTIGATING" className="bg-slate-900">INVESTIGATING</option>
                <option value="RESOLVED" className="bg-slate-900">RESOLVED</option>
                <option value="FALSE_POSITIVE" className="bg-slate-900">FALSE POSITIVE</option>
              </select>
            </div>
          </div>

          {hasActiveFilters && (
            <button
              type="button"
              onClick={handleResetFilters}
              className="text-xs text-slate-400 hover:text-white flex items-center space-x-1 px-2 py-1 rounded bg-slate-800 border border-slate-700 transition-all cursor-pointer"
            >
              <X className="w-3 h-3" />
              <span>Reset Filters</span>
            </button>
          )}
        </div>
      </div>

      {/* Incident List Table */}
      {error && (
        <div className="p-3.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
          <button
            onClick={fetchIncidents}
            className="px-2.5 py-1 rounded bg-red-500/20 hover:bg-red-500/30 text-red-300 font-semibold cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden shadow-sm">
        <div className="p-3.5 border-b border-slate-800 flex items-center justify-between text-xs">
          <div className="flex items-center space-x-2">
            <span className="font-semibold text-white uppercase tracking-wider text-[11px]">
              Incident Records
            </span>
            <span className="px-2 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
              {incidents.length} of {metrics.total}
            </span>
          </div>

          <span className="text-[11px] text-slate-500 hidden sm:inline">
            Select a row to review details and response playbook
          </span>
        </div>

        {loading && incidents.length === 0 ? (
          <div className="p-10 text-center text-slate-400 text-xs flex flex-col items-center space-y-2">
            <RefreshCw className="w-5 h-5 animate-spin" />
            <span>Loading incidents from registry...</span>
          </div>
        ) : incidents.length === 0 ? (
          <div className="p-10 text-center space-y-2 text-xs">
            <div className="w-10 h-10 rounded-lg bg-slate-800 mx-auto flex items-center justify-center text-slate-400">
              <Search className="w-5 h-5" />
            </div>
            <div className="font-semibold text-slate-200">No Incidents Found</div>
            <p className="text-slate-400 max-w-xs mx-auto text-[11px]">
              No recorded security events match your current filter criteria.
            </p>
            {hasActiveFilters && (
              <button
                type="button"
                onClick={handleResetFilters}
                className="mt-1 text-xs px-3 py-1 rounded bg-slate-800 border border-slate-700 text-slate-300 hover:text-white cursor-pointer"
              >
                Reset Filters
              </button>
            )}
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {incidents.map((incident) => {
              const threatIcon = THREAT_ICONS[incident.threat_type] || AlertTriangle;
              const ThreatIconComp = threatIcon;
              const severityMeta = SEVERITY_THEMES[incident.risk_level] || SEVERITY_THEMES.MEDIUM;
              const statusMeta = STATUS_CONFIG[incident.status] || STATUS_CONFIG.NEW;
              const isSelected = selectedIncident?.incident_id === incident.incident_id;

              return (
                <div
                  key={incident.incident_id}
                  onClick={() => setSelectedIncident(incident)}
                  className={`p-3.5 hover:bg-slate-800/40 transition-all cursor-pointer flex flex-col lg:flex-row lg:items-center justify-between gap-3 group ${
                    isSelected ? 'bg-slate-800/50 border-l-2 border-l-blue-500' : ''
                  }`}
                >
                  <div className="space-y-1 flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={(e) => handleCopyId(incident.incident_id, e)}
                        className="inline-flex items-center space-x-1 text-xs font-mono font-semibold text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-2 py-0.5 rounded cursor-pointer transition-all"
                        title="Copy Incident ID"
                      >
                        <span>{incident.incident_id}</span>
                        {copiedId === incident.incident_id ? (
                          <Check className="w-3 h-3 text-emerald-400" />
                        ) : (
                          <Copy className="w-3 h-3 text-slate-400" />
                        )}
                      </button>

                      <span className="inline-flex items-center space-x-1 text-[11px] px-2 py-0.2 rounded bg-slate-800 text-slate-300 border border-slate-700/60">
                        <ThreatIconComp className="w-3 h-3 text-slate-400" />
                        <span>{incident.threat_type}</span>
                      </span>

                      <span className="text-[11px] text-slate-400 flex items-center space-x-1 font-mono">
                        <Clock className="w-3 h-3" />
                        <span>{formatTimestamp(incident.timestamp)}</span>
                      </span>

                      {incident.correlation && incident.correlation.related && (
                        <span className="inline-flex items-center space-x-1 text-[10px] font-mono px-1.5 py-0.2 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30">
                          <span>Linked ({incident.correlation.related_incident_ids?.length || 0})</span>
                        </span>
                      )}
                    </div>

                    <div className="text-xs font-semibold text-slate-200 truncate">
                      {incident.classification}
                    </div>

                    <p className="text-[11px] text-slate-400 line-clamp-1">
                      {incident.explanation}
                    </p>
                  </div>

                  <div className="flex items-center justify-between lg:justify-end gap-3 shrink-0 text-xs">
                    {/* Risk Score */}
                    <div className="flex items-center space-x-2">
                      <div className="text-right">
                        <div className="font-mono font-bold text-slate-100 text-sm">
                          {incident.risk_score}
                          <span className="text-[10px] text-slate-500 font-normal">/100</span>
                        </div>
                        <div className={`text-[10px] font-semibold uppercase ${severityMeta.text}`}>
                          {incident.risk_level}
                        </div>
                      </div>

                      <div className="w-12 h-1.5 bg-slate-950 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${severityMeta.bar}`}
                          style={{ width: `${Math.max(8, incident.risk_score)}%` }}
                        />
                      </div>
                    </div>

                    {/* Status Pill */}
                    <div className="flex items-center space-x-1.5">
                      <span className={`inline-flex items-center space-x-1 text-[11px] font-mono px-2 py-0.5 rounded border ${statusMeta.color}`}>
                        <span className={`w-1.5 h-1.5 rounded-full ${statusMeta.dot}`} />
                        <span>{statusMeta.label}</span>
                      </span>

                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedIncident(incident);
                        }}
                        className="p-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white transition-all cursor-pointer"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Incident Detail Modal */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 lg:p-6 overflow-y-auto animate-fade-in">
          <div 
            className="bg-[#0e1422] border border-slate-700 rounded-xl w-full max-w-3xl max-h-[90vh] flex flex-col shadow-2xl overflow-hidden relative my-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Modal Header */}
            <div className="p-4 border-b border-slate-800 flex items-start justify-between bg-slate-900/90 shrink-0">
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="text-xs font-mono font-bold text-slate-200 bg-slate-800 border border-slate-700 px-2 py-0.5 rounded">
                    {selectedIncident.incident_id}
                  </span>
                  <span className="text-[11px] px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300">
                    {selectedIncident.threat_type}
                  </span>
                  <span className="text-[11px] text-slate-400 flex items-center space-x-1 font-mono">
                    <Clock className="w-3 h-3" />
                    <span>{formatTimestamp(selectedIncident.timestamp)}</span>
                  </span>
                </div>
                <h3 className="text-base font-bold text-white mt-1">
                  {selectedIncident.classification}
                </h3>
              </div>

              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="text-slate-400 hover:text-white p-1.5 rounded-lg hover:bg-slate-800 transition-all cursor-pointer"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="p-5 overflow-y-auto space-y-5 flex-1 text-xs">
              {/* Incident Status Controls */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="space-y-0.5">
                  <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                    Incident Status
                  </div>
                  <div className="text-slate-400 text-[11px]">
                    Update triage status for tracking
                  </div>
                </div>

                <div className="flex flex-wrap items-center gap-1.5">
                  {['NEW', 'INVESTIGATING', 'RESOLVED', 'FALSE_POSITIVE'].map((st) => {
                    const isCurrent = selectedIncident.status === st;
                    const stMeta = STATUS_CONFIG[st];
                    return (
                      <button
                        key={st}
                        type="button"
                        disabled={updatingStatus || isCurrent}
                        onClick={() => handleUpdateStatus(selectedIncident.incident_id, st)}
                        className={`px-2.5 py-1 rounded text-xs font-mono font-medium transition-all border cursor-pointer disabled:opacity-50 ${
                          isCurrent
                            ? `${stMeta.color} ring-1 ring-slate-400`
                            : 'bg-slate-950 hover:bg-slate-800 border-slate-800 text-slate-400 hover:text-slate-200'
                        }`}
                      >
                        {stMeta.label}
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Risk Assessment Overview */}
              {(() => {
                const sevMeta = SEVERITY_THEMES[selectedIncident.risk_level] || SEVERITY_THEMES.MEDIUM;
                const SevIcon = sevMeta.icon;
                return (
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center space-x-3">
                        <div className={`p-2 rounded-lg ${sevMeta.badge}`}>
                          <SevIcon className="w-5 h-5" />
                        </div>
                        <div>
                          <div className="text-[11px] uppercase text-slate-400 font-semibold">
                            Risk Assessment
                          </div>
                          <div className="flex items-baseline space-x-2">
                            <span className="text-2xl font-bold text-white font-mono">
                              {selectedIncident.risk_score}
                            </span>
                            <span className="text-xs text-slate-500 font-mono">/ 100</span>
                            <span className={`text-xs font-semibold uppercase ml-1 ${sevMeta.text}`}>
                              {selectedIncident.risk_level} Severity
                            </span>
                          </div>
                        </div>
                      </div>

                      <div className="text-[11px] text-slate-400 bg-slate-950 px-2.5 py-1 rounded border border-slate-800">
                        {selectedIncident.threat_type}
                      </div>
                    </div>

                    <div className="w-full h-1.5 bg-slate-950 rounded-full overflow-hidden">
                      <div
                        className={`h-full ${sevMeta.bar}`}
                        style={{ width: `${Math.max(4, selectedIncident.risk_score)}%` }}
                      />
                    </div>

                    <div className="pt-2 border-t border-slate-800">
                      <div className="text-[11px] font-semibold text-slate-300 mb-1">
                        Threat Analysis & Details
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/80">
                        {selectedIncident.explanation}
                      </p>
                    </div>
                  </div>
                );
              })()}

              {/* ========================================== */}
              {/* AI SECURITY ANALYST PANEL */}
              {/* ========================================== */}
              {(() => {
                const currentAnalysis = aiAnalysisMap[selectedIncident.incident_id];
                const chatHistory = chatHistoryMap[selectedIncident.incident_id] || [];
                const isAvailable = currentAnalysis && !currentAnalysis.is_fallback && currentAnalysis.status === 'ai';
                const isFallback = currentAnalysis && (currentAnalysis.is_fallback || currentAnalysis.status === 'fallback');

                return (
                  <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
                    {/* Panel Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800 pb-3">
                      <div className="flex items-center space-x-2.5">
                        <div className="p-1.5 rounded-lg bg-indigo-500/10 border border-indigo-500/30 text-indigo-400">
                          <Bot className="w-4 h-4" />
                        </div>
                        <div>
                          <div className="flex items-center space-x-2">
                            <h4 className="text-xs font-bold text-white uppercase tracking-wider">
                              AI SECURITY ANALYST
                            </h4>
                            {/* Honest Status Badge */}
                            {isAvailable ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                                AI Analyst: Available
                              </span>
                            ) : isFallback ? (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                                AI Analyst: Fallback Mode
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-medium bg-slate-800 text-slate-400 border border-slate-700">
                                AI Analyst: Ready
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-slate-400">
                            Evidence-grounded analytical interpretation and prioritized investigation
                          </p>
                        </div>
                      </div>

                      <button
                        type="button"
                        disabled={aiLoading}
                        onClick={() => handleGenerateAiAnalysis(selectedIncident.incident_id)}
                        className="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center justify-center space-x-1.5 transition-all shadow-sm cursor-pointer disabled:opacity-50 shrink-0"
                      >
                        {aiLoading ? (
                          <>
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                            <span>Analyzing Evidence...</span>
                          </>
                        ) : (
                          <>
                            <Sparkles className="w-3.5 h-3.5" />
                            <span>{currentAnalysis ? 'Regenerate AI Analysis' : 'Generate AI Analysis'}</span>
                          </>
                        )}
                      </button>
                    </div>

                    {/* AI Error Notification */}
                    {aiError && (
                      <div className="p-2.5 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center justify-between">
                        <span>{aiError}</span>
                        <button
                          type="button"
                          onClick={() => handleGenerateAiAnalysis(selectedIncident.incident_id)}
                          className="underline text-[11px] font-semibold hover:text-red-300 cursor-pointer"
                        >
                          Retry
                        </button>
                      </div>
                    )}

                    {/* Generated AI Analysis Content */}
                    {currentAnalysis && (
                      <div className="space-y-3.5 pt-1">
                        {/* Threat Summary */}
                        <div className="space-y-1">
                          <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Threat Summary
                          </div>
                          <p className="text-xs text-slate-200 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/80">
                            {currentAnalysis.summary}
                          </p>
                        </div>

                        {/* Why It Matters */}
                        <div className="space-y-1">
                          <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Why It Matters
                          </div>
                          <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/80">
                            {currentAnalysis.why_it_matters}
                          </p>
                        </div>

                        {/* Key Evidence */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Key Evidence
                          </div>
                          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1.5">
                            {currentAnalysis.key_evidence?.map((item, idx) => (
                              <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                                <span className="text-indigo-400 font-bold shrink-0">•</span>
                                <span className="leading-relaxed">{item}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Investigation Steps */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Investigation Steps
                          </div>
                          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1.5">
                            {currentAnalysis.investigation_steps?.map((step, idx) => (
                              <div key={idx} className="flex items-start space-x-2.5 text-xs text-slate-300">
                                <span className="w-4 h-4 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/80 text-[10px] font-mono font-bold flex items-center justify-center shrink-0 mt-0.5">
                                  {idx + 1}
                                </span>
                                <span className="leading-relaxed">{step}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Recommended Actions */}
                        <div className="space-y-1.5">
                          <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider">
                            Recommended Actions
                          </div>
                          <div className="bg-slate-950 p-2.5 rounded border border-slate-800/80 space-y-1.5">
                            {currentAnalysis.recommended_actions?.map((act, idx) => (
                              <div key={idx} className="flex items-start space-x-2 text-xs text-slate-300">
                                <span className="text-emerald-400 font-bold shrink-0">•</span>
                                <span className="leading-relaxed">{act}</span>
                              </div>
                            ))}
                          </div>
                        </div>

                        {/* Limitations */}
                        <div className="space-y-1">
                          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                            Limitations
                          </div>
                          <p className="text-[11px] text-slate-400 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/60 italic">
                            {currentAnalysis.limitations}
                          </p>
                        </div>
                      </div>
                    )}

                    {/* Ask about this incident... */}
                    <div className="pt-3 border-t border-slate-800 space-y-3">
                      <div>
                        <div className="text-[11px] font-semibold text-slate-300 uppercase tracking-wider mb-0.5">
                          Ask about this incident...
                        </div>
                        <p className="text-[11px] text-slate-500">
                          Evidence-grounded query answering scoped strictly to this incident's telemetry.
                        </p>
                      </div>

                      {/* Suggested Questions */}
                      <div className="space-y-1.5">
                        <div className="text-[10px] text-slate-500 uppercase font-mono">Suggested questions:</div>
                        <div className="flex flex-wrap gap-1.5">
                          {[
                            'Why is this incident risky?',
                            'What evidence supports this classification?',
                            'What should I investigate first?',
                            'Are there related incidents?'
                          ].map((sq, sqIdx) => (
                            <button
                              key={sqIdx}
                              type="button"
                              disabled={chatLoading}
                              onClick={() => handleAskAiQuestion(selectedIncident.incident_id, sq)}
                              className="text-[11px] px-2.5 py-1 rounded-full bg-slate-950 hover:bg-slate-800 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white transition-all cursor-pointer text-left"
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
                          handleAskAiQuestion(selectedIncident.incident_id);
                        }}
                        className="flex items-center space-x-2"
                      >
                        <input
                          type="text"
                          value={chatInput}
                          onChange={(e) => setChatInput(e.target.value)}
                          placeholder="Ask about this incident..."
                          disabled={chatLoading}
                          className="flex-1 bg-slate-950 border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500 transition-all"
                        />
                        <button
                          type="submit"
                          disabled={chatLoading || !chatInput.trim()}
                          className="px-3.5 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 disabled:bg-slate-800 text-white disabled:text-slate-500 text-xs font-semibold flex items-center space-x-1 transition-all cursor-pointer disabled:cursor-not-allowed shrink-0"
                        >
                          {chatLoading ? (
                            <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                          ) : (
                            <>
                              <span>Ask</span>
                              <Send className="w-3 h-3" />
                            </>
                          )}
                        </button>
                      </form>

                      {/* Chat Error */}
                      {chatError && (
                        <div className="p-2 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-xs">
                          {chatError}
                        </div>
                      )}

                      {/* Chat History */}
                      {chatHistory.length > 0 && (
                        <div className="space-y-2.5 pt-1">
                          {chatHistory.map((item, cIdx) => (
                            <div key={cIdx} className="bg-slate-950 rounded-lg p-3 border border-slate-800/80 space-y-2 text-xs">
                              <div className="flex items-start space-x-2 text-slate-300">
                                <span className="font-semibold text-indigo-400 shrink-0">Q:</span>
                                <span className="font-medium text-slate-200">{item.question}</span>
                              </div>
                              <div className="flex items-start space-x-2 text-slate-300 pt-1.5 border-t border-slate-800/60">
                                <span className="font-semibold text-emerald-400 shrink-0">A:</span>
                                <div className="space-y-1 flex-1">
                                  <p className="leading-relaxed text-slate-300 whitespace-pre-line">
                                    {item.answer}
                                  </p>
                                  <div className="text-[10px] text-slate-500 font-mono">
                                    {item.status === 'ai' && !item.is_fallback
                                      ? 'AI Analyst: Available'
                                      : 'AI Analyst: Fallback Mode'}
                                  </div>
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })()}

              {/* Related Activity / Correlation Section */}
              {selectedIncident.correlation && (
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-2.5">
                    <div className="flex items-center space-x-2">
                      <Layers className="w-4 h-4 text-blue-400" />
                      <h4 className="text-xs font-semibold text-white uppercase tracking-wider">
                        Related Activity & Similar Incidents
                      </h4>
                    </div>
                    <div className="flex items-center space-x-2">
                      <span
                        className={`text-[11px] font-mono px-2 py-0.5 rounded border font-semibold ${
                          selectedIncident.correlation.related
                            ? selectedIncident.correlation.correlation_score >= 80
                              ? 'bg-red-500/10 text-red-400 border-red-500/30'
                              : selectedIncident.correlation.correlation_score >= 60
                              ? 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                              : 'bg-amber-400/10 text-amber-400 border-amber-400/30'
                            : 'bg-slate-950 text-slate-400 border-slate-800'
                        }`}
                      >
                        {selectedIncident.correlation.related
                          ? `⚠ Related Activity (${selectedIncident.correlation.correlation_score}/100)`
                          : 'No Significant Relationship (0/100)'}
                      </span>
                    </div>
                  </div>

                  {/* Matched Signals */}
                  {selectedIncident.correlation.matched_signals && selectedIncident.correlation.matched_signals.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] text-slate-400 font-medium">Matched Signals:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.correlation.matched_signals.map((sig, sIdx) => (
                          <span
                            key={sIdx}
                            className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300 flex items-center space-x-1"
                          >
                            <span className="text-blue-400">•</span>
                            <span>{SIGNAL_LABELS[sig] || sig.replace(/_/g, ' ')}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Related Incidents List */}
                  {selectedIncident.correlation.related_incident_ids && selectedIncident.correlation.related_incident_ids.length > 0 && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] text-slate-400 font-medium">Potentially Related Incident IDs:</div>
                      <div className="flex flex-wrap gap-1.5">
                        {selectedIncident.correlation.related_incident_ids.map((relId, rIdx) => {
                          const relInc = incidents.find((i) => i.incident_id === relId);
                          const relObj = selectedIncident.correlation.relationships?.find((r) => r.incident_id === relId);
                          const threatType = relInc?.threat_type || relObj?.threat_type;
                          return (
                            <button
                              key={rIdx}
                              type="button"
                              onClick={() => {
                                if (relInc) setSelectedIncident(relInc);
                              }}
                              className="text-xs font-mono px-2 py-0.5 rounded bg-blue-500/10 hover:bg-blue-500/20 text-blue-300 border border-blue-500/30 transition-all cursor-pointer flex items-center space-x-1"
                              title={`Jump to ${relId}`}
                            >
                              <span>{relId}</span>
                              {threatType && <span className="text-[10px] text-slate-400">({threatType})</span>}
                            </button>
                          );
                        })}
                      </div>
                    </div>
                  )}

                  {/* Dynamic Reason */}
                  <div className="pt-1">
                    <p className="text-xs text-slate-300 leading-relaxed bg-slate-950 p-2.5 rounded border border-slate-800/80">
                      {selectedIncident.correlation.reason}
                    </p>
                  </div>

                  {/* Advisory Notice */}
                  <div className="p-2 bg-slate-950 border border-slate-800/60 rounded text-[10px] text-slate-500 flex items-start space-x-1.5">
                    <Info className="w-3 h-3 text-slate-500 shrink-0 mt-0.5" />
                    <span>
                      Deterministic similarity based on observable telemetry signals. Does not prove a confirmed coordinated attack campaign.
                    </span>
                  </div>
                </div>
              )}

              {/* Security Evidence */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2.5">
                <div className="flex items-center justify-between">
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span>Security Evidence ({selectedIncident.evidence?.length || 0})</span>
                  </h4>
                </div>

                {selectedIncident.evidence && selectedIncident.evidence.length > 0 ? (
                  <div className="space-y-1.5">
                    {selectedIncident.evidence.map((ev, idx) => (
                      <div
                        key={idx}
                        className="bg-slate-950 border border-slate-800 rounded p-2.5 space-y-0.5"
                      >
                        <div className="text-xs font-semibold text-amber-300">
                          {ev.indicator}
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          {ev.details}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="p-2.5 bg-slate-950 border border-slate-800 text-slate-400 rounded text-xs">
                    No technical indicators were flagged for this event.
                  </div>
                )}
              </div>

              {/* Source Telemetry Data */}
              {selectedIncident.source_data && Object.keys(selectedIncident.source_data).length > 0 && (
                <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2.5">
                  <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                    <FileText className="w-3.5 h-3.5 text-blue-400" />
                    <span>Event Telemetry</span>
                  </h4>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {Object.entries(selectedIncident.source_data).map(([key, val]) => {
                      if (!val && val !== 0) return null;
                      return (
                        <div
                          key={key}
                          className="bg-slate-950 border border-slate-800 rounded p-2 space-y-0.5"
                        >
                          <div className="text-[10px] uppercase text-slate-400">
                            {key.replace(/_/g, ' ')}
                          </div>
                          <div className="text-xs font-mono text-slate-200 break-all">
                            {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* Recommended Actions Playbook */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-2.5">
                <h4 className="text-xs font-semibold text-white uppercase tracking-wider flex items-center space-x-1.5">
                  <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                  <span>Recommended Actions</span>
                </h4>

                <div className="space-y-1.5">
                  {(selectedIncident.recommended_actions && selectedIncident.recommended_actions.length > 0
                    ? selectedIncident.recommended_actions
                    : [
                        'Review security logs for abnormal activity.',
                        'Verify sender or user identity out-of-band.',
                        'Avoid accessing unverified links or downloading attachments.',
                        'Initiate credential reset through official channels if compromise is suspected.'
                      ]
                  ).map((action, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded p-2.5 flex items-start space-x-2 text-xs text-slate-300"
                    >
                      <span className="w-4 h-4 rounded bg-slate-800 text-slate-300 font-mono text-[10px] flex items-center justify-center shrink-0 mt-0.5">
                        {idx + 1}
                      </span>
                      <span className="leading-relaxed">{action}</span>
                    </div>
                  ))}
                </div>

                <div className="p-2.5 bg-slate-950 border border-slate-800 rounded text-[11px] text-slate-400 flex items-start space-x-2">
                  <Info className="w-3.5 h-3.5 text-slate-400 shrink-0 mt-0.5" />
                  <span>
                    Advisory recommendations only. CYBERGUARD does not automatically execute account locks or external communications.
                  </span>
                </div>
              </div>

              {/* Raw JSON Payload */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
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
                    <pre>{JSON.stringify(selectedIncident, null, 2)}</pre>
                  </div>
                )}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="p-3.5 border-t border-slate-800 bg-slate-900/90 flex items-center justify-end shrink-0">
              <button
                type="button"
                onClick={() => setSelectedIncident(null)}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium transition-all cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
