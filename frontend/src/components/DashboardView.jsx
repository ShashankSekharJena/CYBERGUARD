import React, { useState, useEffect, useMemo } from 'react';
import { 
  Server, 
  ShieldCheck, 
  CheckCircle2, 
  ArrowRight, 
  Activity, 
  Terminal, 
  Layers, 
  Mail, 
  UserCheck, 
  Key, 
  Globe, 
  AlertTriangle, 
  AlertCircle, 
  ShieldAlert, 
  Clock, 
  RefreshCw, 
  BellRing, 
  Check, 
  ChevronRight, 
  TrendingUp, 
  FileText, 
  Shield, 
  Zap 
} from 'lucide-react';
import { getIncidents } from '../services/api';

const PIPELINE_STEPS = [
  { step: '01', title: 'Detection', desc: 'Ingest message, URL & auth data', icon: Zap },
  { step: '02', title: 'Classification', desc: 'Identify threat indicators', icon: Layers },
  { step: '03', title: 'Risk Score', desc: 'Compute 0-100 severity score', icon: TrendingUp },
  { step: '04', title: 'Explanation', desc: 'Generate analyst summary', icon: FileText },
  { step: '05', title: 'Incident Creation', desc: 'Log event to incident registry', icon: ShieldAlert },
  { step: '06', title: 'Alert', desc: 'Flag critical unresolved items', icon: BellRing },
  { step: '07', title: 'Response', desc: 'Apply defensive recommendations', icon: ShieldCheck }
];

export default function DashboardView({
  onTestConnection,
  backendResponse,
  loading: pingLoading,
  setActiveTab
}) {
  const [incidentsData, setIncidentsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [acknowledgedAlerts, setAcknowledgedAlerts] = useState(new Set());
  const [toastMessage, setToastMessage] = useState(null);

  const showToast = (msg) => {
    setToastMessage(msg);
    setTimeout(() => setToastMessage(null), 3000);
  };

  const fetchDashboardData = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getIncidents({ sort_by: 'timestamp', order: 'desc' });
      if (res.success && res.data) {
        setIncidentsData(res.data);
      } else {
        setError(res.error || 'Failed to fetch incident telemetry');
      }
    } catch (err) {
      setError(err.message || 'Error communicating with backend');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const totalIncidents = incidentsData?.total || 0;
  const criticalCount = incidentsData?.critical_count || 0;
  const highCount = incidentsData?.high_count || 0;
  const mediumCount = incidentsData?.medium_count || 0;
  const lowCount = (incidentsData?.low_count || 0) + (incidentsData?.safe_count || 0);
  const resolvedCount = incidentsData?.resolved_count || 0;
  const totalAnalyzed = incidentsData?.total_analyzed_count || Math.max(totalIncidents, 6);

  const phishingCount = incidentsData?.phishing_count || 0;
  const urlCount = incidentsData?.url_threat_count || 0;
  const impersonationCount = incidentsData?.impersonation_count || 0;
  const accountSecurityCount = incidentsData?.account_security_count || 0;

  const categoryTotal = phishingCount + urlCount + impersonationCount + accountSecurityCount || 1;
  const phishPct = Math.round((phishingCount / categoryTotal) * 100);
  const urlPct = Math.round((urlCount / categoryTotal) * 100);
  const impPct = Math.round((impersonationCount / categoryTotal) * 100);
  const accPct = Math.round((accountSecurityCount / categoryTotal) * 100);

  const riskTotal = totalIncidents || 1;
  const critPct = Math.round((criticalCount / riskTotal) * 100);
  const highPct = Math.round((highCount / riskTotal) * 100);
  const medPct = Math.round((mediumCount / riskTotal) * 100);
  const lowPct = Math.round((lowCount / riskTotal) * 100);

  const activeAlerts = useMemo(() => {
    if (!incidentsData?.incidents) return [];
    return incidentsData.incidents
      .filter((inc) => 
        (inc.risk_level === 'CRITICAL' || inc.risk_level === 'HIGH') &&
        inc.status !== 'RESOLVED' &&
        inc.status !== 'FALSE_POSITIVE' &&
        !acknowledgedAlerts.has(inc.incident_id)
      )
      .slice(0, 4);
  }, [incidentsData, acknowledgedAlerts]);

  const recentIncidents = useMemo(() => {
    if (!incidentsData?.incidents) return [];
    return incidentsData.incidents.slice(0, 5);
  }, [incidentsData]);

  const handleAcknowledgeAlert = (incidentId, e) => {
    e.stopPropagation();
    setAcknowledgedAlerts((prev) => new Set([...prev, incidentId]));
    showToast(`Alert for ${incidentId} acknowledged.`);
  };

  const formatTime = (isoString) => {
    if (!isoString) return 'Just now';
    try {
      const date = new Date(isoString);
      return date.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
    } catch {
      return isoString;
    }
  };

  return (
    <div className="space-y-8 max-w-7xl mx-auto px-6 py-8">
      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 z-50 bg-white border border-slate-200 text-slate-700 text-sm px-4 py-3 rounded-lg shadow-lg flex items-center space-x-2">
          <CheckCircle2 className="w-5 h-5 text-emerald-600 shrink-0" />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-900 tracking-tight">
            Threat Operations Dashboard
          </h1>
          <p className="text-sm text-slate-600 mt-1">
            Consolidated telemetry from Phishing, URL Threat, Impersonation, and Account Security detection modules.
          </p>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={fetchDashboardData}
            disabled={loading}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-white border border-slate-300 text-slate-700 hover:bg-slate-50 transition-all disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} />
            <span>{loading ? 'Refreshing...' : 'Refresh'}</span>
          </button>

          <button
            onClick={() => setActiveTab('incident-center')}
            className="flex items-center space-x-2 px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white font-medium transition-all cursor-pointer"
          >
            <ShieldAlert className="w-4 h-4" />
            <span>Incident Center</span>
          </button>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* Total Analyzed */}
        <div className="bg-white border border-slate-200 rounded-lg p-4">
          <div className="text-sm text-slate-600">Total Analyzed</div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{totalAnalyzed}</div>
          <div className="text-xs text-slate-500 mt-1">Total events evaluated</div>
        </div>

        {/* Total Incidents */}
        <div 
          onClick={() => setActiveTab('incident-center')}
          className="bg-white border border-slate-200 rounded-lg p-4 hover:border-blue-300 cursor-pointer transition-all"
        >
          <div className="text-sm text-slate-600 flex items-center justify-between">
            <span>Total Incidents</span>
            {incidentsData?.linked_count > 0 && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-blue-100 text-blue-700">
                {incidentsData.linked_count} Linked
              </span>
            )}
          </div>
          <div className="text-2xl font-bold text-slate-900 mt-1">{totalIncidents}</div>
          <div className="text-xs text-slate-500 mt-1">Recorded in registry</div>
        </div>

        {/* Critical */}
        <div 
          onClick={() => setActiveTab('incident-center')}
          className="bg-white border border-slate-200 rounded-lg p-4 hover:border-red-300 cursor-pointer transition-all"
        >
          <div className="text-sm text-red-600 font-medium flex items-center justify-between">
            <span>Critical</span>
            <AlertCircle className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-red-600 mt-1">{criticalCount}</div>
          <div className="text-xs text-slate-500 mt-1">Score 80–100</div>
        </div>

        {/* High Risk */}
        <div 
          onClick={() => setActiveTab('incident-center')}
          className="bg-white border border-slate-200 rounded-lg p-4 hover:border-orange-300 cursor-pointer transition-all"
        >
          <div className="text-sm text-orange-600 font-medium flex items-center justify-between">
            <span>High Risk</span>
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-orange-600 mt-1">{highCount}</div>
          <div className="text-xs text-slate-500 mt-1">Score 70–79</div>
        </div>

        {/* Medium Risk */}
        <div 
          onClick={() => setActiveTab('incident-center')}
          className="bg-white border border-slate-200 rounded-lg p-4 hover:border-amber-300 cursor-pointer transition-all"
        >
          <div className="text-sm text-amber-600 font-medium flex items-center justify-between">
            <span>Medium Risk</span>
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-amber-600 mt-1">{mediumCount}</div>
          <div className="text-xs text-slate-500 mt-1">Score 40–69</div>
        </div>

        {/* Resolved */}
        <div 
          onClick={() => setActiveTab('incident-center')}
          className="bg-white border border-slate-200 rounded-lg p-4 hover:border-emerald-300 cursor-pointer transition-all"
        >
          <div className="text-sm text-emerald-600 font-medium flex items-center justify-between">
            <span>Resolved</span>
            <ShieldCheck className="w-4 h-4" />
          </div>
          <div className="text-2xl font-bold text-emerald-600 mt-1">{resolvedCount}</div>
          <div className="text-xs text-slate-500 mt-1">Closed incidents</div>
        </div>
      </div>

      {/* Active Alerts */}
      <div className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <BellRing className="w-5 h-5 text-red-600" />
            <h2 className="text-base font-semibold text-slate-900">Active Alerts</h2>
          </div>
          <span className="text-sm px-3 py-1 rounded-full bg-red-100 text-red-700 font-medium">
            {activeAlerts.length} Unresolved High/Critical
          </span>
        </div>

        {activeAlerts.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            <CheckCircle2 className="w-8 h-8 text-emerald-600 mx-auto mb-2" />
            <div className="font-medium text-slate-700">No Active High-Severity Alerts</div>
            <p className="text-sm mt-1">
              All critical and high-risk incidents have been acknowledged or triaged.
            </p>
          </div>
        ) : (
          <div className="space-y-3">
            {activeAlerts.map((alert) => (
              <div
                key={alert.incident_id}
                onClick={() => setActiveTab('incident-center')}
                className="p-4 bg-slate-50 border border-slate-200 hover:border-slate-300 rounded-lg cursor-pointer transition-all"
              >
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-mono font-semibold text-slate-900">
                      {alert.incident_id}
                    </span>
                    <span className={`text-xs px-2 py-1 rounded font-semibold ${
                      alert.risk_level === 'CRITICAL'
                        ? 'bg-red-100 text-red-700'
                        : 'bg-orange-100 text-orange-700'
                    }`}>
                      {alert.risk_level} ({alert.risk_score})
                    </span>
                    <span className="text-sm text-slate-600">
                      {alert.threat_type}
                    </span>
                  </div>

                  <span className="text-xs text-slate-500 font-mono flex items-center space-x-1">
                    <Clock className="w-3 h-3" />
                    <span>{formatTime(alert.timestamp)}</span>
                  </span>
                </div>

                <div className="text-sm text-slate-700 mb-3">
                  {alert.classification}
                </div>

                <div className="flex items-center justify-between">
                  <button
                    type="button"
                    onClick={(e) => handleAcknowledgeAlert(alert.incident_id, e)}
                    className="text-sm text-slate-600 hover:text-emerald-600 flex items-center space-x-1 px-3 py-1.5 rounded bg-white border border-slate-300 hover:border-emerald-300 transition-all cursor-pointer"
                  >
                    <Check className="w-4 h-4" />
                    <span>Acknowledge</span>
                  </button>

                  <div className="text-blue-600 hover:text-blue-700 flex items-center space-x-1 text-sm font-medium cursor-pointer">
                    <span>Investigate</span>
                    <ChevronRight className="w-4 h-4" />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recent Incidents */}
      <div className="bg-white border border-slate-200 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center space-x-2">
            <Activity className="w-5 h-5 text-slate-600" />
            <h2 className="text-base font-semibold text-slate-900">Recent Incident Activity</h2>
          </div>
          <button
            onClick={() => setActiveTab('incident-center')}
            className="text-sm text-blue-600 hover:text-blue-700 flex items-center space-x-1 cursor-pointer font-medium"
          >
            <span>View All Incidents</span>
            <ChevronRight className="w-4 h-4" />
          </button>
        </div>

        {recentIncidents.length === 0 ? (
          <div className="p-8 text-center text-slate-500">
            No incidents recorded. Run any detector to log an event.
          </div>
        ) : (
          <div className="divide-y divide-slate-200">
            {recentIncidents.map((inc) => (
              <div
                key={inc.incident_id}
                onClick={() => setActiveTab('incident-center')}
                className="py-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-slate-50 px-2 cursor-pointer transition-all"
              >
                <div className="flex items-center space-x-3 min-w-0">
                  <span className="text-sm font-mono font-semibold text-slate-900">
                    {inc.incident_id}
                  </span>
                  <span className="text-sm px-2 py-1 rounded bg-slate-100 text-slate-700 font-medium">
                    {inc.threat_type}
                  </span>
                  <span className="text-sm text-slate-700 truncate">
                    {inc.classification}
                  </span>
                </div>

                <div className="flex items-center space-x-3 shrink-0 self-end sm:self-auto">
                  <span className={`text-xs px-2 py-1 rounded font-semibold font-medium ${
                    inc.risk_level === 'CRITICAL' ? 'bg-red-100 text-red-700' :
                    inc.risk_level === 'HIGH' ? 'bg-orange-100 text-orange-700' :
                    inc.risk_level === 'MEDIUM' ? 'bg-amber-100 text-amber-700' :
                    'bg-emerald-100 text-emerald-700'
                  }`}>
                    {inc.risk_level} ({inc.risk_score})
                  </span>

                  <span className="text-sm text-slate-500 font-mono">
                    {formatTime(inc.timestamp)}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
