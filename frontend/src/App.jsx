import React, { useState, useEffect } from 'react';
import Sidebar from './components/Sidebar';
import Navbar from './components/Navbar';
import DashboardView from './components/DashboardView';
import PhishingAnalyzerView from './components/PhishingAnalyzerView';
import UrlAnalyzerView from './components/UrlAnalyzerView';
import ImpersonationAnalyzerView from './components/ImpersonationAnalyzerView';
import AccountSecurityView from './components/AccountSecurityView';
import IncidentCenterView from './components/IncidentCenterView';
import AiSecurityAnalystView from './components/AiSecurityAnalystView';
import { testBackendConnection } from './services/api';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendResponse, setBackendResponse] = useState(null);
  const [backendStatus, setBackendStatus] = useState({ online: false, latencyMs: null });
  const [loading, setLoading] = useState(false);

  // Function to call GET / and update state
  const handleTestConnection = async () => {
    setLoading(true);
    const result = await testBackendConnection();
    setBackendResponse(result);
    setBackendStatus({
      online: result.success,
      latencyMs: result.latencyMs,
    });
    setLoading(false);
  };

  // Ping on initial load
  useEffect(() => {
    handleTestConnection();
  }, []);

  return (
    <div className="flex h-screen w-full bg-slate-50 text-slate-900 overflow-hidden">
      {/* Left Sidebar */}
      <Sidebar 
        activeTab={activeTab} 
        setActiveTab={setActiveTab} 
        backendStatus={backendStatus} 
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden bg-white">
        {/* Top Navbar */}
        <Navbar 
          activeTab={activeTab} 
          onTestConnection={handleTestConnection} 
          loading={loading} 
        />

        {/* Dynamic Page Content View */}
        <main className="flex-1 overflow-y-auto">
          {activeTab === 'dashboard' && (
            <DashboardView
              onTestConnection={handleTestConnection}
              backendResponse={backendResponse}
              loading={loading}
              setActiveTab={setActiveTab}
            />
          )}

          {activeTab === 'phishing' && <PhishingAnalyzerView />}

          {activeTab === 'url-analyzer' && <UrlAnalyzerView />}

          {activeTab === 'impersonation' && <ImpersonationAnalyzerView />}

          {activeTab === 'account-security' && <AccountSecurityView />}

          {activeTab === 'incident-center' && (
            <IncidentCenterView onTestConnection={handleTestConnection} />
          )}

          {activeTab === 'ai-security-analyst' && <AiSecurityAnalystView />}
        </main>
      </div>
    </div>
  );
}
