export const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

export async function testBackendConnection() {
  const startTime = performance.now();
  try {
    const response = await fetch(`${API_BASE_URL}/`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    const elapsed = Math.round(performance.now() - startTime);
    if (!response.ok) {
      throw new Error(`HTTP Error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json();
    return {
      success: true,
      data,
      latencyMs: elapsed,
      status: response.status,
    };
  } catch (error) {
    const elapsed = Math.round(performance.now() - startTime);
    return {
      success: false,
      error: error.message || 'Failed to connect to backend',
      latencyMs: elapsed,
    };
  }
}

export async function fetchMlMetrics() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/ml/metrics`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzePhishing(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/phishing`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzeUrl(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/url`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzeImpersonation(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/impersonation`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzeMultimodal(formData) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/multimodal`, {
      method: 'POST',
      body: formData,
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzeLogin(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function analyzeAccountSecurity(payload) {
  try {
    const response = await fetch(`${API_BASE_URL}/analyze/account-security`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function getIncidents(params = {}) {
  try {
    const query = new URLSearchParams();
    if (params.threat_type && params.threat_type !== 'ALL') {
      query.append('threat_type', params.threat_type);
    }
    if (params.risk_level && params.risk_level !== 'ALL') {
      query.append('risk_level', params.risk_level);
    }
    if (params.status && params.status !== 'ALL') {
      query.append('status', params.status);
    }
    if (params.search && params.search.trim()) {
      query.append('search', params.search.trim());
    }
    if (params.sort_by) {
      query.append('sort_by', params.sort_by);
    }
    if (params.order) {
      query.append('order', params.order);
    }

    const queryString = query.toString() ? `?${query.toString()}` : '';
    const response = await fetch(`${API_BASE_URL}/incidents${queryString}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function getIncidentById(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/incidents/${encodeURIComponent(incidentId)}`, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function updateIncidentStatus(incidentId, status) {
  try {
    const response = await fetch(`${API_BASE_URL}/incidents/${encodeURIComponent(incidentId)}/status`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ status }),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function fetchIncidentCorrelation(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/incidents/${encodeURIComponent(incidentId)}/correlate`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function fetchIncidentMitre(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/incidents/${encodeURIComponent(incidentId)}/mitre`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function fetchIncidentPlaybook(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/api/incidents/${encodeURIComponent(incidentId)}/playbook`, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function fetchIncidentAiAnalysis(incidentId) {
  try {
    const response = await fetch(`${API_BASE_URL}/incidents/${encodeURIComponent(incidentId)}/ai-analysis`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

export async function askIncidentAiChat(incidentId, question) {
  try {
    const response = await fetch(`${API_BASE_URL}/incidents/${encodeURIComponent(incidentId)}/ai-chat`, {
      method: 'POST',
      headers: {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ question }),
    });
    const data = await response.json();
    return { success: response.ok, data };
  } catch (error) {
    return { success: false, error: error.message };
  }
}
