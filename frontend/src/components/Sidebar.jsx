import React from 'react';
import { 
  ShieldAlert, 
  LayoutDashboard, 
  MailWarning, 
  Globe, 
  UserX, 
  ShieldCheck, 
  AlertTriangle, 
  Server,
  Bot
} from 'lucide-react';
import { API_BASE_URL } from '../services/api';

export default function Sidebar({ activeTab, setActiveTab, backendStatus }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'phishing', label: 'Phishing Analyzer', icon: MailWarning },
    { id: 'url-analyzer', label: 'URL Threat Analyzer', icon: Globe },
    { id: 'impersonation', label: 'Impersonation Analyzer', icon: UserX },
    { id: 'account-security', label: 'Account Security', icon: ShieldCheck },
    { id: 'incident-center', label: 'Incident Center', icon: AlertTriangle },
    { id: 'ai-security-analyst', label: 'AI Security Analyst', icon: Bot },
  ];

  return (
    <aside className="w-64 bg-white border-r border-slate-200 flex flex-col justify-between shrink-0">
      <div>
        {/* Brand Header */}
        <div className="p-6 border-b border-slate-200">
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-blue-600 text-white rounded-lg">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="font-bold text-lg tracking-tight text-slate-900">
                CYBERGUARD
              </div>
              <p className="text-xs text-slate-500">Security Operations Console</p>
            </div>
          </div>
        </div>

        {/* Navigation */}
        <nav className="p-4 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-btn-${item.id}`}
                onClick={() => setActiveTab(item.id)}
                className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-blue-50 text-blue-700'
                    : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'
                }`}
              >
                <Icon className={`w-5 h-5 ${isActive ? 'text-blue-600' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Backend Status Widget */}
      <div className="p-4 border-t border-slate-200">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center space-x-2 text-slate-600 text-sm">
            <Server className="w-4 h-4" />
            <span>API Server</span>
          </div>
          <span
            className={`flex items-center text-xs px-2 py-1 rounded-full font-medium ${
              backendStatus?.online
                ? 'bg-emerald-100 text-emerald-700'
                : 'bg-red-100 text-red-700'
            }`}
          >
            <span
              className={`w-1.5 h-1.5 rounded-full mr-1.5 ${
                backendStatus?.online ? 'bg-emerald-500' : 'bg-red-500'
              }`}
            />
            {backendStatus?.online ? 'Online' : 'Offline'}
          </span>
        </div>
        <div className="text-xs text-slate-500 font-mono">
          Host: <span className="text-slate-700">{new URL(API_BASE_URL).host}</span>
        </div>
        {backendStatus?.latencyMs !== undefined && (
          <div className="text-xs text-slate-500 font-mono mt-1 flex items-center justify-between">
            <span>Latency</span>
            <span className="text-slate-700">{backendStatus.latencyMs} ms</span>
          </div>
        )}
      </div>
    </aside>
  );
}
