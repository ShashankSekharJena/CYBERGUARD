import React from 'react';
import { RefreshCw, Server } from 'lucide-react';

export default function Navbar({ activeTab, onTestConnection, loading }) {
  const titles = {
    dashboard: 'Threat Intelligence Dashboard',
    phishing: 'Phishing Threat Detection',
    'url-analyzer': 'URL Threat Analyzer',
    impersonation: 'Digital Impersonation Detection',
    'account-security': 'Account Security & Anomaly Analysis',
    'incident-center': 'Security Incident Center',
    'ai-security-analyst': 'AI Security Analyst',
  };

  return (
    <header className="h-16 border-b border-slate-200 bg-white px-6 flex items-center justify-between shrink-0">
      <div className="flex items-center space-x-3">
        <h1 className="text-lg font-semibold text-slate-900">
          {titles[activeTab] || 'Threat Console'}
        </h1>
      </div>

      <div className="flex items-center space-x-3">
        <button
          id="navbar-test-conn-btn"
          onClick={onTestConnection}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 rounded-lg text-sm bg-slate-100 hover:bg-slate-200 text-slate-700 transition-all disabled:opacity-50 cursor-pointer"
        >
          <RefreshCw className={`w-4 h-4 text-slate-500 ${loading ? 'animate-spin' : ''}`} />
          <span>{loading ? 'Checking...' : 'Check API Status'}</span>
        </button>
      </div>
    </header>
  );
}
