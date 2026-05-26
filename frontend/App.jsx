import React, { useState, useEffect, useCallback } from 'react';
import { ChevronRight, Shield, Lock, Plus, Edit2, Trash2, Eye, BarChart3, Download, Upload } from 'lucide-react';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';
import SoarFlowViewer from './src/components/SoarFlowViewer';

// ============================================================================
// API SERVICE LAYER
// ============================================================================

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

class APIService {
  constructor() {
    this.token = localStorage.getItem('auth_token');
  }

  setToken(token) {
    this.token = token;
    localStorage.setItem('auth_token', token);
  }

  getHeaders() {
    return {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${this.token}`,
    };
  }

  async request(url, options = {}) {
    const response = await fetch(url, options);
    if (response.status === 401) {
      localStorage.removeItem('auth_token');
      localStorage.removeItem('user_role');
      this.token = null;
      window.location.reload();
      throw new Error('Session expired');
    }
    return response;
  }

  async login(username, password) {
    const response = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
    if (!response.ok) throw new Error('Login failed');
    const data = await response.json();
    this.setToken(data.access_token);
    return data;
  }

  async getFrameworks() {
    const response = await this.request(`${API_BASE}/frameworks`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch frameworks');
    return await response.json();
  }

  async getFrameworkVectors(framework) {
    const response = await this.request(`${API_BASE}/frameworks/${framework}/vectors`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch vectors');
    return await response.json();
  }

  async getModelsForVector(framework, vectorId) {
    const response = await this.request(
      `${API_BASE}/frameworks/${framework}/vectors/${vectorId}/models`,
      { headers: this.getHeaders() }
    );
    if (!response.ok) throw new Error('Failed to fetch models');
    return await response.json();
  }

  async getModelDetails(modelId) {
    const response = await this.request(`${API_BASE}/models/${modelId}`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch model details');
    return await response.json();
  }

  async createParser(modelId, parser) {
    const response = await this.request(`${API_BASE}/parsers?model_id=${modelId}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(parser),
    });
    if (!response.ok) throw new Error('Failed to create parser');
    return await response.json();
  }

  async createCorrelationRule(modelId, rule) {
    let url = `${API_BASE}/correlation-rules`;
    if (modelId) url += `?model_id=${modelId}`;
    const response = await this.request(url, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(rule),
    });
    if (!response.ok) throw new Error('Failed to create correlation rule');
    return await response.json();
  }

  async createSOARFlow(modelId, flow) {
    const response = await this.request(`${API_BASE}/soar-flows?model_id=${modelId}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(flow),
    });
    if (!response.ok) throw new Error('Failed to create SOAR flow');
    return await response.json();
  }

  async importData(type, modelId, data) {
    let url = `${API_BASE}/import/${type}`;
    if (modelId) url += `?model_id=${modelId}`;
    const response = await this.request(url, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify({ items: data }),
    });
    if (!response.ok) throw new Error(`Failed to import ${type}`);
    return await response.json();
  }

  async importCorrelationRulesCSV(file) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await this.request(`${API_BASE}/import/correlation-rules/csv`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
      body: formData,
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to import CSV');
    }
    return await response.json();
  }

  async exportCorrelationRulesCSV() {
    const response = await this.request(`${API_BASE}/export/correlation-rules/csv`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });
    if (!response.ok) throw new Error('Failed to export CSV');
    return await response.blob();
  }

  async importParsersText(modelId, file) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await this.request(`${API_BASE}/import/parsers/text?model_id=${modelId}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
      body: formData,
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to import parsers text file');
    }
    return await response.json();
  }

  async exportParsersText(modelId) {
    const response = await this.request(`${API_BASE}/export/parsers/text/${modelId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });
    if (!response.ok) throw new Error('Failed to export parsers');
    return await response.blob();
  }

  async importSOARFlowsFile(modelId, file) {
    const formData = new FormData();
    formData.append('file', file);
    const response = await this.request(`${API_BASE}/import/soar-flows/file?model_id=${modelId}`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
      body: formData,
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to import SOAR flows file');
    }
    return await response.json();
  }

  async exportSOARFlows(modelId) {
    const response = await this.request(`${API_BASE}/export/soar-flows/${modelId}`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${this.token}`,
      },
    });
    if (!response.ok) throw new Error('Failed to export SOAR flows');
    return await response.blob();
  }

  async createHighlight(modelId, data) {
    const response = await this.request(`${API_BASE}/models/${modelId}/highlights`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(data),
    });
    if (!response.ok) throw new Error('Failed to create highlight');
    return await response.json();
  }
}

const api = new APIService();

// ============================================================================
// COMPONENTS
// ============================================================================

// LOGIN PAGE
function LoginPage({ onLogin }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const data = await api.login(username, password);
      onLogin(data.role);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-black flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        <div className="bg-slate-800/50 backdrop-blur border border-slate-700 rounded-lg p-8 shadow-2xl">
          <div className="flex items-center justify-center mb-8">
            <Shield className="w-10 h-10 text-blue-400 mr-3" />
            <h1 className="text-3xl font-bold text-white">SecIntel</h1>
          </div>

          <h2 className="text-xl font-semibold text-white mb-6 text-center">
            Cybersecurity Intelligence Dashboard
          </h2>

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Username
              </label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="analyst"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded text-white placeholder-gray-400 focus:outline-none focus:border-blue-500"
                placeholder="••••••••"
              />
            </div>

            {error && (
              <div className="bg-red-500/10 border border-red-500/50 text-red-300 px-4 py-2 rounded text-sm">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded transition disabled:opacity-50"
            >
              {loading ? 'Logging in...' : 'Login'}
            </button>
          </form>

          <div className="mt-6 p-4 bg-slate-700/50 rounded text-xs text-gray-400">
            <p className="font-semibold mb-2">Demo Credentials:</p>
            <p>analyst / demo (read-only)</p>
            <p>admin / demo (manage artifacts)</p>
            <p>superadmin / demo (full control)</p>
          </div>
        </div>
      </div>
    </div>
  );
}

// FRAMEWORK SELECTOR
function FrameworkSelector({ onSelectFramework }) {
  const [frameworks, setFrameworks] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchFrameworks = async () => {
      try {
        const data = await api.getFrameworks();
        setFrameworks(data);
      } catch (err) {
        console.error('Failed to fetch frameworks:', err);
      }
      setLoading(false);
    };
    fetchFrameworks();
  }, []);

  if (loading) {
    return <div className="text-center py-8 text-gray-400">Loading frameworks...</div>;
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-2xl mx-auto">
      {frameworks.map((fw) => (
        <button
          key={fw.id}
          onClick={() => onSelectFramework(fw.name)}
          className="p-6 bg-gradient-to-br from-slate-700 to-slate-800 border border-slate-600 rounded-lg hover:border-blue-500 hover:from-slate-600 transition group text-left"
        >
          <h3 className="text-xl font-bold text-white mb-2 uppercase">
            {fw.name}
          </h3>
          <p className="text-gray-400 mb-4">{fw.description}</p>
          <div className="flex items-center text-blue-400 group-hover:text-blue-300">
            <span className="text-sm font-semibold">Explore</span>
            <ChevronRight className="w-4 h-4 ml-2" />
          </div>
        </button>
      ))}
    </div>
  );
}

// VECTOR LIST
function VectorList({ framework, onSelectVector, onBack }) {
  const [vectors, setVectors] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchVectors = async () => {
      try {
        const data = await api.getFrameworkVectors(framework);
        setVectors(data);
      } catch (err) {
        console.error('Failed to fetch vectors:', err);
      }
      setLoading(false);
    };
    fetchVectors();
  }, [framework]);

  if (loading) {
    return <div className="text-center py-8 text-gray-400">Loading vectors...</div>;
  }

  return (
    <div>
      <button
        onClick={onBack}
        className="mb-6 text-blue-400 hover:text-blue-300 flex items-center gap-2"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Frameworks
      </button>

      <h2 className="text-2xl font-bold text-white mb-6 capitalize">
        {framework} Framework - Tactics/Functions
      </h2>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {vectors.map((vector) => (
          <button
            key={vector.id}
            onClick={() => onSelectVector(vector.id, vector.name)}
            className="p-4 bg-slate-700/50 border border-slate-600 rounded hover:border-blue-500 hover:bg-slate-700 transition text-left"
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="text-blue-400 text-sm font-mono mb-1">
                  {vector.external_id}
                </div>
                <h3 className="text-lg font-semibold text-white mb-2">
                  {vector.name}
                </h3>
                <p className="text-gray-400 text-sm">{vector.description}</p>
              </div>
              <ChevronRight className="w-5 h-5 text-gray-400 mt-1 flex-shrink-0" />
            </div>
          </button>
        ))}
      </div>
    </div>
  );
}

// MODEL LISTING (grouped by source type → brand → model)
function ModelListing({ framework, vectorId, vectorName, onSelectModel, onBack }) {
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filterBrand, setFilterBrand] = useState('all');

  useEffect(() => {
    const fetchModels = async () => {
      try {
        const data = await api.getModelsForVector(framework, vectorId);
        setModels(data);
      } catch (err) {
        console.error('Failed to fetch models:', err);
      }
      setLoading(false);
    };
    fetchModels();
  }, [framework, vectorId]);

  if (loading) {
    return <div className="text-center py-8 text-gray-400">Loading models...</div>;
  }

  // Group models by source type → brand
  const grouped = models.reduce((acc, model) => {
    if (!acc[model.source_type]) acc[model.source_type] = {};
    if (!acc[model.source_type][model.brand]) {
      acc[model.source_type][model.brand] = [];
    }
    acc[model.source_type][model.brand].push(model);
    return acc;
  }, {});

  const brands = Array.from(new Set(models.map((m) => m.brand)));

  return (
    <div>
      <button
        onClick={onBack}
        className="mb-6 text-blue-400 hover:text-blue-300 flex items-center gap-2"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Vectors
      </button>

      <div className="mb-6">
        <h2 className="text-2xl font-bold text-white mb-2">
          {vectorName}
        </h2>
        <p className="text-gray-400">Source Models Mapped to This Vector</p>
      </div>

      <div className="mb-6">
        <label className="text-sm text-gray-300 mr-4">Filter by Brand:</label>
        <select
          value={filterBrand}
          onChange={(e) => setFilterBrand(e.target.value)}
          className="px-3 py-1 bg-slate-700 border border-slate-600 rounded text-white text-sm"
        >
          <option value="all">All Brands</option>
          {brands.map((brand) => (
            <option key={brand} value={brand}>
              {brand}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-8">
        {Object.entries(grouped).map(([sourceType, brands_dict]) => (
          <div key={sourceType}>
            <h3 className="text-lg font-bold text-blue-400 mb-4 uppercase">
              {sourceType}
            </h3>
            <div className="space-y-4">
              {Object.entries(brands_dict).map(([brand, modelList]) => {
                if (filterBrand !== 'all' && brand !== filterBrand) return null;
                return (
                  <div key={brand} className="pl-4 border-l-2 border-slate-600">
                    <h4 className="text-white font-semibold mb-3">{brand}</h4>
                    <div className="space-y-2">
                      {modelList.map((model) => (
                        <button
                          key={model.model_id}
                          onClick={() => onSelectModel(model.model_id, model.model)}
                          className="w-full text-left p-3 bg-slate-700/50 border border-slate-600 rounded hover:border-blue-500 hover:bg-slate-700 transition flex items-center justify-between"
                        >
                          <span className="text-gray-200">{model.model}</span>
                          <Eye className="w-4 h-4 text-gray-400" />
                        </button>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// MODEL DETAIL VIEW WITH TABS
function ModelDetail({ modelId, modelName, onBack, userRole }) {
  const [details, setDetails] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [showCreateParser, setShowCreateParser] = useState(false);
  const [showCreateRule, setShowCreateRule] = useState(false);
  const [highlightTitle, setHighlightTitle] = useState('');
  const [highlightContent, setHighlightContent] = useState('');
  const [highlightPriority, setHighlightPriority] = useState('medium');

  const refreshDetails = async () => {
    try {
      const refreshed = await api.getModelDetails(modelId);
      setDetails(refreshed);
    } catch (err) {
      console.error('Failed to refresh details:', err);
    }
  };

  const [toasts, setToasts] = useState([]);

  const showToast = useCallback((message, type = 'success', duration = 5000) => {
    const id = Date.now() + Math.random().toString(36).substr(2, 9);
    setToasts((prev) => [...prev, { id, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, duration);
  }, []);

  const handleExport = (type) => {
    let data;
    if (type === 'correlation-rules') data = details.correlation_rules;
    if (type === 'parsers') data = details.parsers;
    if (type === 'soar-flows') data = details.soar_flows;
    
    try {
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${type}_export.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('JSON export completed!', 'success');
    } catch (err) {
      showToast(`JSON export failed: ${err.message}`, 'error');
    }
  };

  const handleImport = async (type, event) => {
    const file = event.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const data = JSON.parse(e.target.result);
        await api.importData(type, modelId, data);
        showToast('JSON import successful!', 'success');
        await refreshDetails();
      } catch (err) {
        showToast(`JSON import failed: ${err.message}`, 'error');
      }
    };
    reader.readAsText(file);
  };

  const handleExportSOARFlows = async () => {
    try {
      const blob = await api.exportSOARFlows(modelId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `soar_flows_export_model_${modelId}.json`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('SOAR flows exported successfully!', 'success');
    } catch (err) {
      showToast(`Export failed: ${err.message}`, 'error');
    }
  };

  const handleImportSOARFlows = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const res = await api.importSOARFlowsFile(modelId, file);
      const successfulInserts = res.successful_inserts || 0;
      showToast(`Import complete: ${successfulInserts} SOAR flows successfully imported!`, 'success');
      await refreshDetails();
    } catch (err) {
      showToast(`Import failed: ${err.message}`, 'error');
    }
  };

  const handleExportCSV = async () => {
    try {
      const blob = await api.exportCorrelationRulesCSV();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `correlation_rules_export.csv`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Correlation rules exported successfully!', 'success');
    } catch (err) {
      showToast(`Export failed: ${err.message}`, 'error');
    }
  };

  const handleImportCSV = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const res = await api.importCorrelationRulesCSV(file);
      const { successful_inserts, failed_rows } = res;
      const failedCount = failed_rows?.length || 0;
      
      if (failedCount > 0) {
        showToast(
          `Import complete: ${successful_inserts} rules successfully imported, ${failedCount} rows failed.`, 
          'warning'
        );
      } else {
        showToast(
          `Import complete: ${successful_inserts} rules successfully imported!`, 
          'success'
        );
      }
      await refreshDetails();
    } catch (err) {
      showToast(`Import failed: ${err.message}`, 'error');
    }
  };

  const handleExportParserText = async () => {
    try {
      const blob = await api.exportParsersText(modelId);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `parsers_export_${modelId}.txt`;
      a.click();
      URL.revokeObjectURL(url);
      showToast('Parsers exported successfully!', 'success');
    } catch (err) {
      showToast(`Export failed: ${err.message}`, 'error');
    }
  };

  const handleImportParserText = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    try {
      const res = await api.importParsersText(modelId, file);
      const { successful_inserts, failed_rows } = res;
      const failedCount = failed_rows?.length || 0;
      
      if (failedCount > 0) {
        showToast(
          `Import complete: ${successful_inserts} parsers successfully imported, ${failedCount} lines failed.`, 
          'warning'
        );
      } else {
        showToast(
          `Import complete: ${successful_inserts} parsers successfully imported!`, 
          'success'
        );
      }
      await refreshDetails();
    } catch (err) {
      showToast(`Import failed: ${err.message}`, 'error');
    }
  };

  const handleCreateHighlight = async (e) => {
    e.preventDefault();
    try {
      await api.createHighlight(modelId, {
        title: highlightTitle,
        content: highlightContent,
        priority: highlightPriority
      });
      setHighlightTitle('');
      setHighlightContent('');
      showToast('Highlight created successfully!', 'success');
      await refreshDetails();
    } catch (err) {
      showToast(`Failed to create highlight: ${err.message}`, 'error');
    }
  };

  useEffect(() => {
    const fetchDetails = async () => {
      try {
        const data = await api.getModelDetails(modelId);
        setDetails(data);
      } catch (err) {
        console.error('Failed to fetch model details:', err);
      }
      setLoading(false);
    };
    fetchDetails();
  }, [modelId]);

  if (loading) {
    return <div className="text-center py-8 text-gray-400">Loading model details...</div>;
  }

  if (!details) {
    return <div className="text-center py-8 text-gray-400">Model not found</div>;
  }

  const tabs = [
    { id: 'overview', label: 'Overview', icon: '📋' },
    { id: 'rules', label: 'Correlation Rules', icon: '🔗' },
    { id: 'parsers', label: 'Parsers', icon: '⚙️' },
    { id: 'soar', label: 'SOAR Flows', icon: '🔄' },
    { id: 'compliance', label: 'Compliance', icon: '✓' },
    { id: 'attacks', label: 'Attack Vectors', icon: '⚔️' },
    { id: 'highlights', label: 'Key Highlights', icon: '⭐' },
  ];

  const canEdit = ['admin', 'super_admin'].includes(userRole);

  return (
    <div>
      <button
        onClick={onBack}
        className="mb-6 text-blue-400 hover:text-blue-300 flex items-center gap-2"
      >
        <ChevronRight className="w-4 h-4 rotate-180" />
        Back to Models
      </button>

      <div className="mb-6">
        <h2 className="text-3xl font-bold text-white mb-2">{modelName}</h2>
        <div className="flex gap-4 text-gray-400">
          <span>Type: {details.source_type}</span>
          <span>Brand: {details.brand}</span>
        </div>
      </div>

      {/* TABS */}
      <div className="mb-6 flex overflow-x-auto gap-2 border-b border-slate-600">
        {tabs.map((tab) => {
          if (tab.admin && !canEdit) return null;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-3 whitespace-nowrap font-medium transition ${
                activeTab === tab.id
                  ? 'text-blue-400 border-b-2 border-blue-400'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {tab.icon} {tab.label}
            </button>
          );
        })}
      </div>

      {/* TAB CONTENT */}
      <div className="bg-slate-800/30 border border-slate-700 rounded-lg p-6">
        {activeTab === 'overview' && (
          <div>
            <h3 className="text-xl font-bold text-white mb-4">Model Information</h3>
            <div className="grid grid-cols-2 gap-4 text-gray-300">
              <div>
                <span className="text-gray-400">Source Type:</span>
                <p className="font-semibold">{details.source_type}</p>
              </div>
              <div>
                <span className="text-gray-400">Brand:</span>
                <p className="font-semibold">{details.brand}</p>
              </div>
              <div className="col-span-2">
                <span className="text-gray-400">Description:</span>
                <p className="font-semibold">{details.description || 'N/A'}</p>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-3 gap-4">
              <div className="bg-slate-700/50 p-4 rounded">
                <div className="text-2xl font-bold text-blue-400">
                  {details.correlation_rules?.length || 0}
                </div>
                <div className="text-sm text-gray-400">Correlation Rules</div>
              </div>
              <div className="bg-slate-700/50 p-4 rounded">
                <div className="text-2xl font-bold text-green-400">
                  {details.parsers?.length || 0}
                </div>
                <div className="text-sm text-gray-400">Parsers</div>
              </div>
              <div className="bg-slate-700/50 p-4 rounded">
                <div className="text-2xl font-bold text-purple-400">
                  {details.soar_flows?.length || 0}
                </div>
                <div className="text-sm text-gray-400">SOAR Flows</div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'rules' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white">Correlation Rules</h3>
              <div className="flex gap-2">
                <button
                  onClick={() => handleExport('correlation-rules')}
                  className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                  title="Export to JSON"
                >
                  <Download className="w-4 h-4" /> Export JSON
                </button>
                <button
                  onClick={() => handleExportCSV()}
                  className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                  title="Export to CSV"
                >
                  <Download className="w-4 h-4" /> Export CSV
                </button>
                {canEdit && (
                  <>
                    <label className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm cursor-pointer" title="Import from JSON">
                      <Upload className="w-4 h-4" /> Import JSON
                      <input type="file" accept=".json" className="hidden" onChange={(e) => handleImport('correlation-rules', e)} />
                    </label>
                    <label className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm cursor-pointer" title="Import from CSV/TXT">
                      <Upload className="w-4 h-4" /> Import CSV
                      <input type="file" accept=".csv,.txt" className="hidden" onChange={(e) => handleImportCSV(e)} />
                    </label>
                    <button
                      onClick={() => setShowCreateRule(!showCreateRule)}
                      className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    >
                      <Plus className="w-4 h-4" /> Add Rule
                    </button>
                  </>
                )}
              </div>
            </div>

            {showCreateRule && canEdit && (
              <CreateRuleForm modelId={modelId} onClose={() => setShowCreateRule(false)} onSuccess={refreshDetails} />
            )}

            <div className="space-y-3">
              {details.correlation_rules?.map((rule) => (
                <div key={rule.id} className="p-4 bg-slate-700/50 rounded border border-slate-600">
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-white">{rule.name}</h4>
                    <span className={`text-xs px-2 py-1 rounded ${
                      rule.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                      rule.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                      rule.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' :
                      'bg-blue-500/20 text-blue-300'
                    }`}>
                      {rule.severity}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400 mb-2">{rule.description}</p>
                  <div className="mt-2 mb-3 text-xs font-mono text-gray-300 bg-slate-800 p-2 rounded overflow-x-auto whitespace-pre-wrap">
                    {typeof rule.rule_logic === 'string'
                      ? rule.rule_logic
                      : JSON.stringify(rule.rule_logic, null, 2)}
                  </div>
                  <div className="text-xs text-gray-500">
                    By {rule.author} • {new Date(rule.created_at).toLocaleDateString()}
                  </div>
                </div>
              ))}
              {!details.correlation_rules?.length && (
                <p className="text-gray-400 text-sm">No correlation rules mapped</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'parsers' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white">Parsers</h3>
              <div className="flex gap-2">
                <button
                  onClick={() => handleExport('parsers')}
                  className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                  title="Export to JSON"
                >
                  <Download className="w-4 h-4" /> Export JSON
                </button>
                <button
                  onClick={() => handleExportParserText()}
                  className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                  title="Export to multi-format text file"
                >
                  <Download className="w-4 h-4" /> Export Text
                </button>
                {canEdit && (
                  <>
                    <label className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm cursor-pointer" title="Import from JSON">
                      <Upload className="w-4 h-4" /> Import JSON
                      <input type="file" accept=".json" className="hidden" onChange={(e) => handleImport('parsers', e)} />
                    </label>
                    <label className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm cursor-pointer" title="Import from multi-format text file">
                      <Upload className="w-4 h-4" /> Import Text
                      <input type="file" accept=".txt" className="hidden" onChange={(e) => handleImportParserText(e)} />
                    </label>
                    <button
                      onClick={() => setShowCreateParser(!showCreateParser)}
                      className="flex items-center gap-2 px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                    >
                      <Plus className="w-4 h-4" /> Add Parser
                    </button>
                  </>
                )}
              </div>
            </div>

            {showCreateParser && canEdit && (
              <CreateParserForm modelId={modelId} onClose={() => setShowCreateParser(false)} onSuccess={refreshDetails} />
            )}

            <div className="space-y-3">
              {details.parsers?.map((parser) => (
                <div key={parser.id} className="p-4 bg-slate-700/50 rounded border border-slate-600">
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-semibold text-white">{parser.name}</h4>
                    <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded">
                      {parser.format.toUpperCase()}
                    </span>
                  </div>
                  <p className="text-sm text-gray-400">{parser.description}</p>
                  {parser.parser_config && (
                    <div className="mt-3">
                      <div className="text-xs text-gray-400 mb-1">Configuration / Columns:</div>
                      <pre className="text-xs text-blue-300 bg-slate-800 p-2 rounded overflow-x-auto whitespace-pre-wrap">
                        {JSON.stringify(parser.parser_config, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              ))}
              {!details.parsers?.length && (
                <p className="text-gray-400 text-sm">No parsers configured</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'soar' && (
          <div>
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xl font-bold text-white">SOAR Workflows</h3>
              <div className="flex gap-2">
                <button
                  onClick={() => handleExportSOARFlows()}
                  className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm"
                >
                  <Download className="w-4 h-4" /> Export
                </button>
                {canEdit && (
                  <label className="flex items-center gap-2 px-3 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm cursor-pointer">
                    <Upload className="w-4 h-4" /> Import
                    <input type="file" accept=".json" className="hidden" onChange={(e) => handleImportSOARFlows(e)} />
                  </label>
                )}
              </div>
            </div>
            <div className="space-y-3">
              {details.soar_flows?.map((flow) => (
                <div key={flow.id} className="p-4 bg-slate-700/50 rounded border border-slate-600">
                  <h4 className="font-semibold text-white mb-2">{flow.name}</h4>
                  <p className="text-sm text-gray-400 mb-4">{flow.description}</p>
                  <SoarFlowViewer 
                    workflow_json={flow.workflow_json}
                    playbook_constructor={flow.workflow_json?.playbook_constructor} 
                    playbook_details={flow.workflow_json?.playbook_details} 
                    steps={flow.workflow_json?.steps} 
                  />
                </div>
              ))}
              {!details.soar_flows?.length && (
                <p className="text-gray-400 text-sm">No SOAR flows configured</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'compliance' && (
          <div>
            <h3 className="text-xl font-bold text-white mb-4">Compliance</h3>
            <div className="space-y-2">
              {details.compliance?.map((c, i) => (
                <div key={i} className="p-3 bg-slate-700/50 rounded text-gray-300">
                  <span className="font-semibold">{c.framework}:</span> {c.requirement}
                </div>
              ))}
              {!details.compliance?.length && (
                <p className="text-gray-400 text-sm">No compliance mappings</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'attacks' && (
          <div>
            <h3 className="text-xl font-bold text-white mb-4">Attack Vectors</h3>
            <div className="space-y-2">
              {details.attack_vectors?.map((a, i) => (
                <div key={i} className="p-3 bg-slate-700/50 rounded text-gray-300">
                  <span className="font-semibold">{a.vector}:</span>
                  <span className="ml-2 text-red-400">{a.severity}</span>
                </div>
              ))}
              {!details.attack_vectors?.length && (
                <p className="text-gray-400 text-sm">No attack vectors</p>
              )}
            </div>
          </div>
        )}

        {activeTab === 'highlights' && (
          <div>
            <h3 className="text-xl font-bold text-white mb-4">Key Highlights</h3>
            {canEdit && (
              <form onSubmit={handleCreateHighlight} className="mb-6 p-4 bg-slate-700/50 border border-slate-600 rounded">
                <h4 className="text-white font-semibold mb-3">Add New Highlight</h4>
                <div className="space-y-3">
                  <input
                    type="text"
                    placeholder="Highlight Title"
                    value={highlightTitle}
                    onChange={(e) => setHighlightTitle(e.target.value)}
                    required
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                  />
                  <textarea
                    placeholder="Content (optional)"
                    value={highlightContent}
                    onChange={(e) => setHighlightContent(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                  />
                  <select
                    value={highlightPriority}
                    onChange={(e) => setHighlightPriority(e.target.value)}
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-600 rounded text-white text-sm"
                  >
                    <option value="low">Low Priority</option>
                    <option value="medium">Medium Priority</option>
                    <option value="high">High Priority</option>
                    <option value="critical">Critical</option>
                  </select>
                  <button type="submit" className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm w-full">
                    Add Highlight
                  </button>
                </div>
              </form>
            )}
            <div className="space-y-3">
              {details.highlights?.map((h, i) => (
                <div key={i} className={`p-4 rounded border-l-4 ${
                  h.priority === 'critical' ? 'bg-red-900/20 border-red-500' :
                  h.priority === 'high' ? 'bg-orange-900/20 border-orange-500' :
                  h.priority === 'medium' ? 'bg-yellow-900/20 border-yellow-500' :
                  'bg-blue-900/20 border-blue-500'
                }`}>
                  <h4 className="font-bold text-white">{h.title}</h4>
                  {h.content && <p className="text-gray-300 text-sm mt-1">{h.content}</p>}
                </div>
              ))}
              {!details.highlights?.length && (
                <p className="text-gray-400 text-sm">No highlights available.</p>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Toast Notifications */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 max-w-sm w-full">
        {toasts.map((toast) => (
          <div
            key={toast.id}
            className={`p-4 rounded shadow-lg border backdrop-blur flex items-start justify-between gap-3 text-sm transition-all duration-300 ${
              toast.type === 'error'
                ? 'bg-red-950/90 border-red-500/50 text-red-200 shadow-red-900/10'
                : toast.type === 'warning'
                ? 'bg-amber-950/90 border-amber-500/50 text-amber-200 shadow-amber-900/10'
                : 'bg-emerald-950/90 border-emerald-500/50 text-emerald-200 shadow-emerald-900/10'
            }`}
          >
            <div className="flex-1">{toast.message}</div>
            <button
              onClick={() => setToasts((prev) => prev.filter((t) => t.id !== toast.id))}
              className="text-gray-400 hover:text-white text-xs font-bold font-mono"
            >
              ✕
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

// CREATE PARSER FORM
function CreateParserForm({ modelId, onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    name: '',
    format: 'json',
    description: '',
    parser_config: {},
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.createParser(modelId, formData);
      onClose();
      if (onSuccess) onSuccess();
    } catch (err) {
      console.error('Failed to create parser:', err);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="mb-4 p-4 bg-slate-700/50 rounded border border-blue-500">
      <input
        type="text"
        placeholder="Parser Name"
        value={formData.name}
        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2"
        required
      />
      <select
        value={formData.format}
        onChange={(e) => setFormData({ ...formData, format: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2"
      >
        {['kv', 'json', 'grok', 'csv', 'cef', 'xml'].map((fmt) => (
          <option key={fmt} value={fmt}>
            {fmt.toUpperCase()}
          </option>
        ))}
      </select>
      <textarea
        placeholder="Description"
        value={formData.description}
        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 h-20"
      />
      <button
        type="submit"
        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
      >
        Create Parser
      </button>
    </form>
  );
}

// CREATE CORRELATION RULE FORM
function CreateRuleForm({ modelId, onClose, onSuccess }) {
  const [formData, setFormData] = useState({
    name: '',
    rule_logic: '',
    description: '',
    author: '',
    severity: 'medium',
    tags: [],
  });

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      await api.createCorrelationRule(modelId, formData);
      onClose();
      if (onSuccess) onSuccess();
    } catch (err) {
      console.error('Failed to create rule:', err);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="mb-4 p-4 bg-slate-700/50 rounded border border-blue-500">
      <input
        type="text"
        placeholder="Rule Name"
        value={formData.name}
        onChange={(e) => setFormData({ ...formData, name: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2"
        required
      />
      <select
        value={formData.severity}
        onChange={(e) => setFormData({ ...formData, severity: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2"
      >
        {['critical', 'high', 'medium', 'low'].map((sev) => (
          <option key={sev} value={sev}>
            {sev.charAt(0).toUpperCase() + sev.slice(1)}
          </option>
        ))}
      </select>
      <textarea
        placeholder="Rule Logic (JSON or expression)"
        value={formData.rule_logic}
        onChange={(e) => setFormData({ ...formData, rule_logic: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 h-20"
        required
      />
      <button
        type="submit"
        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
      >
        Create Rule
      </button>
    </form>
  );
}

// ============================================================================
// MAIN APP
// ============================================================================

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('auth_token'));
  const [userRole, setUserRole] = useState(localStorage.getItem('user_role') || 'analyst');
  const [currentPage, setCurrentPage] = useState('frameworks');
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [selectedVector, setSelectedVector] = useState(null);
  const [selectedVectorName, setSelectedVectorName] = useState(null);
  const [selectedModel, setSelectedModel] = useState(null);
  const [selectedModelName, setSelectedModelName] = useState(null);

  const handleLogin = (role) => {
    setIsLoggedIn(true);
    setUserRole(role);
    localStorage.setItem('auth_token', api.token);
    localStorage.setItem('user_role', role);
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_role');
    api.token = null;
    setCurrentPage('frameworks');
  };

  if (!isLoggedIn) {
    return <LoginPage onLogin={handleLogin} userRole={userRole} />;
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-black">
      {/* HEADER */}
      <header className="bg-slate-800/50 backdrop-blur border-b border-slate-700 sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <BarChart3 className="w-8 h-8 text-blue-400" />
            <h1 className="text-2xl font-bold text-white">SecIntel</h1>
          </div>
          <div className="flex items-center gap-4">
            <span className="text-gray-400 text-sm">
              Role: <span className="font-semibold text-blue-400 capitalize">{userRole}</span>
            </span>
            <button
              onClick={handleLogout}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm transition"
            >
              Logout
            </button>
          </div>
        </div>
      </header>

      {/* MAIN CONTENT */}
      <main className="max-w-7xl mx-auto px-6 py-12">
        {currentPage === 'frameworks' && (
          <FrameworkSelector
            onSelectFramework={(fw) => {
              setSelectedFramework(fw);
              setCurrentPage('vectors');
            }}
          />
        )}

        {currentPage === 'vectors' && selectedFramework && (
          <VectorList
            framework={selectedFramework}
            onSelectVector={(id, name) => {
              setSelectedVector(id);
              setSelectedVectorName(name);
              setCurrentPage('models');
            }}
            onBack={() => {
              setCurrentPage('frameworks');
              setSelectedFramework(null);
            }}
          />
        )}

        {currentPage === 'models' && selectedFramework && selectedVector && (
          <ModelListing
            framework={selectedFramework}
            vectorId={selectedVector}
            vectorName={selectedVectorName}
            onSelectModel={(id, name) => {
              setSelectedModel(id);
              setSelectedModelName(name);
              setCurrentPage('detail');
            }}
            onBack={() => setCurrentPage('vectors')}
          />
        )}

        {currentPage === 'detail' && selectedModel && (
          <ModelDetail
            modelId={selectedModel}
            modelName={selectedModelName}
            userRole={userRole}
            onBack={() => setCurrentPage('models')}
          />
        )}
      </main>
    </div>
  );
}
