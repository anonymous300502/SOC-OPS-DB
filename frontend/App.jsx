import React, { useState, useEffect, useCallback } from 'react';
import { ChevronRight, Shield, Lock, Plus, Edit2, Trash2, Eye, BarChart3, Download, Upload } from 'lucide-react';
import ReactFlow, { Background, Controls, MiniMap } from 'reactflow';
import 'reactflow/dist/style.css';
import SoarFlowViewer from './src/components/SoarFlowViewer';

// ============================================================================
// API SERVICE LAYER
// ============================================================================

// Default to a same-origin path so the browser talks to nginx (port 80/443),
// which proxies /api/* to the backend over the internal network. This avoids
// CORS and does not depend on the backend port being published to the host.
// Override with VITE_API_URL only for split deployments (e.g. a separate API host).
const API_BASE = import.meta.env.VITE_API_URL || '/api';

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

  // -- Framework hierarchy drill-down --
  async getVector(vectorId) {
    const response = await this.request(`${API_BASE}/vectors/${vectorId}`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch vector');
    return await response.json();
  }

  async searchVectors(framework, q, level) {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (level) params.set('level', level);
    const response = await this.request(
      `${API_BASE}/frameworks/${framework}/vectors/search?${params.toString()}`,
      { headers: this.getHeaders() }
    );
    if (!response.ok) throw new Error('Failed to search vectors');
    return await response.json();
  }

  // -- Source catalog CRUD --
  async getSourceTypes() { return this._get('/source-types', 'source types'); }
  async getBrands() { return this._get('/brands', 'brands'); }
  async getSourceModels() { return this._get('/source-models', 'source models'); }

  async createSourceType(data) { return this._post('/source-types', data, 'source type'); }
  async createBrand(data) { return this._post('/brands', data, 'brand'); }
  async createSourceModel(data) { return this._post('/source-models', data, 'source model'); }

  deleteSourceType(id) { return this._delete(`/source-types/${id}`, 'source type'); }
  deleteBrand(id) { return this._delete(`/brands/${id}`, 'brand'); }
  deleteSourceModel(id) { return this._delete(`/source-models/${id}`, 'source model'); }

  // -- Model <-> framework vector (TTP) mapping --
  async getModelVectors(modelId) { return this._get(`/models/${modelId}/framework-vectors`, 'mappings'); }
  async mapModelVectors(modelId, vectorIds) {
    return this._post(`/models/${modelId}/framework-vectors`, { vector_ids: vectorIds }, 'mapping');
  }
  unmapModelVector(modelId, vectorId) {
    return this._delete(`/models/${modelId}/framework-vectors/${vectorId}`, 'mapping');
  }

  async _get(path, label) {
    const response = await this.request(`${API_BASE}${path}`, { headers: this.getHeaders() });
    if (!response.ok) throw new Error(`Failed to fetch ${label}`);
    return await response.json();
  }

  async _post(path, body, label) {
    const response = await this.request(`${API_BASE}${path}`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Failed to create ${label}`);
    }
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

  async importCorrelationRulesCSV(modelId, file) {
    const formData = new FormData();
    formData.append('file', file);
    let url = `${API_BASE}/import/correlation-rules/csv`;
    if (modelId) url += `?model_id=${modelId}`;
    const response = await this.request(url, {
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

  async _delete(path, label) {
    const response = await this.request(`${API_BASE}${path}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || `Failed to delete ${label}`);
    }
    return await response.json();
  }

  deleteParser(id) { return this._delete(`/parsers/${id}`, 'parser'); }
  deleteCorrelationRule(id) { return this._delete(`/correlation-rules/${id}`, 'correlation rule'); }
  deleteSOARFlow(id) { return this._delete(`/soar-flows/${id}`, 'SOAR flow'); }
  deleteHighlight(id) { return this._delete(`/highlights/${id}`, 'highlight'); }

  // -- User management (admin+) --
  async getMe() {
    const response = await this.request(`${API_BASE}/auth/me`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch current user');
    return await response.json();
  }

  async getUsers() {
    const response = await this.request(`${API_BASE}/auth/users`, {
      headers: this.getHeaders(),
    });
    if (!response.ok) throw new Error('Failed to fetch users');
    return await response.json();
  }

  async createUser(user) {
    const response = await this.request(`${API_BASE}/auth/users`, {
      method: 'POST',
      headers: this.getHeaders(),
      body: JSON.stringify(user),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to create user');
    }
    return await response.json();
  }

  async updateUser(userId, update) {
    const response = await this.request(`${API_BASE}/auth/users/${userId}`, {
      method: 'PATCH',
      headers: this.getHeaders(),
      body: JSON.stringify(update),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to update user');
    }
    return await response.json();
  }

  async deleteUser(userId) {
    const response = await this.request(`${API_BASE}/auth/users/${userId}`, {
      method: 'DELETE',
      headers: this.getHeaders(),
    });
    if (!response.ok) {
      const errData = await response.json().catch(() => ({}));
      throw new Error(errData.detail || 'Failed to delete user');
    }
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
      onLogin(data.role, data.username);
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
                placeholder="Username"
                autoComplete="username"
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
                autoComplete="current-password"
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

          <p className="mt-6 text-center text-xs text-gray-500">
            Access is managed by your administrator. Contact them if you need an account.
          </p>
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

// VECTOR EXPLORER (recursive drill-down through the framework hierarchy)
function levelLabel(level, plural = true) {
  const map = {
    tactic: 'Tactic', technique: 'Technique', subtechnique: 'Sub-technique',
    function: 'Function', category: 'Category', subcategory: 'Subcategory',
  };
  const base = map[level] || 'Item';
  return plural ? `${base}s` : base;
}

function VectorCard({ vec, onOpen }) {
  return (
    <button
      onClick={() => onOpen(vec)}
      className="p-4 bg-slate-700/50 border border-slate-600 rounded hover:border-blue-500 hover:bg-slate-700 transition text-left w-full"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-blue-400 text-xs font-mono mb-1">{vec.external_id}</div>
          <h3 className="text-base font-semibold text-white">{vec.name}</h3>
          {vec.description && (
            <p className="text-gray-400 text-xs mt-1 line-clamp-2">{vec.description}</p>
          )}
          <div className="flex flex-wrap gap-2 mt-2">
            {vec.level && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-600/60 text-slate-300 capitalize">
                {vec.level}
              </span>
            )}
            {vec.child_count > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-300">
                {vec.child_count} {levelLabel(vec.level === 'tactic' ? 'technique' : vec.level === 'technique' ? 'subtechnique' : vec.level === 'function' ? 'category' : 'subcategory').toLowerCase()}
              </span>
            )}
            {vec.model_count > 0 && (
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300">
                {vec.model_count} source{vec.model_count > 1 ? 's' : ''}
              </span>
            )}
          </div>
        </div>
        <ChevronRight className="w-5 h-5 text-gray-400 mt-1 flex-shrink-0" />
      </div>
    </button>
  );
}

function VectorExplorer({ framework, onSelectModel, onBack }) {
  const [stack, setStack] = useState([]); // breadcrumb of opened vectors
  const [topVectors, setTopVectors] = useState(null);
  const [node, setNode] = useState(null); // current node detail (when stack non-empty)
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [searchResults, setSearchResults] = useState(null);

  const loadTop = useCallback(async () => {
    setLoading(true);
    setStack([]);
    setNode(null);
    setSearchResults(null);
    try {
      setTopVectors(await api.getFrameworkVectors(framework));
    } catch (err) {
      console.error('Failed to load framework vectors:', err);
    }
    setLoading(false);
  }, [framework]);

  useEffect(() => { loadTop(); }, [loadTop]);

  const openVector = async (vec) => {
    setLoading(true);
    try {
      const detail = await api.getVector(vec.id);
      setNode(detail);
      setStack((prev) => {
        const idx = prev.findIndex((s) => s.id === vec.id);
        if (idx >= 0) return prev.slice(0, idx + 1);
        return [...prev, { id: vec.id, external_id: vec.external_id, name: vec.name, level: vec.level }];
      });
      setSearchResults(null);
    } catch (err) {
      console.error('Failed to open vector:', err);
    }
    setLoading(false);
  };

  const doSearch = async (e) => {
    e.preventDefault();
    const q = search.trim();
    if (!q) { setSearchResults(null); return; }
    setLoading(true);
    try {
      setSearchResults(await api.searchVectors(framework, q));
    } catch (err) {
      console.error('Search failed:', err);
    }
    setLoading(false);
  };

  const children = node ? node.children : topVectors || [];

  return (
    <div>
      <button onClick={onBack} className="mb-4 text-blue-400 hover:text-blue-300 flex items-center gap-2">
        <ChevronRight className="w-4 h-4 rotate-180" /> Back to Frameworks
      </button>

      {/* Breadcrumb */}
      <div className="flex flex-wrap items-center gap-1 mb-4 text-sm">
        <button onClick={loadTop} className="text-blue-400 hover:text-blue-300 font-semibold uppercase">
          {framework}
        </button>
        {stack.map((s, i) => (
          <span key={s.id} className="flex items-center gap-1">
            <ChevronRight className="w-3 h-3 text-gray-500" />
            <button
              onClick={() => (i === stack.length - 1 ? null : openVector(s))}
              className={i === stack.length - 1 ? 'text-white font-mono' : 'text-blue-400 hover:text-blue-300 font-mono'}
            >
              {s.external_id}
            </button>
          </span>
        ))}
      </div>

      {/* Search */}
      <form onSubmit={doSearch} className="mb-6 flex gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder={`Search ${framework.toUpperCase()} (e.g. T1059, PowerShell, DE.CM)`}
          className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
        />
        <button type="submit" className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">
          Search
        </button>
        {searchResults && (
          <button type="button" onClick={() => { setSearch(''); setSearchResults(null); }}
            className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded text-sm">
            Clear
          </button>
        )}
      </form>

      {loading ? (
        <div className="text-center py-8 text-gray-400">Loading…</div>
      ) : searchResults ? (
        <div>
          <h2 className="text-lg font-bold text-white mb-3">
            {searchResults.length} result{searchResults.length !== 1 ? 's' : ''} for “{search}”
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {searchResults.map((v) => <VectorCard key={v.id} vec={v} onOpen={openVector} />)}
            {searchResults.length === 0 && <p className="text-gray-400 text-sm">No matches.</p>}
          </div>
        </div>
      ) : (
        <div>
          {node && (
            <div className="mb-6">
              <div className="text-blue-400 text-sm font-mono">{node.external_id}</div>
              <h2 className="text-2xl font-bold text-white">{node.name}</h2>
              {node.description && <p className="text-gray-400 mt-2 text-sm max-w-3xl">{node.description}</p>}
              {node.parents && node.parents.length > 1 && (
                <p className="text-xs text-gray-500 mt-2">
                  Also appears under: {node.parents.map((p) => p.external_id).join(', ')}
                </p>
              )}
            </div>
          )}

          {/* Mapped source models at this node */}
          {node && node.models && node.models.length > 0 && (
            <div className="mb-8">
              <h3 className="text-lg font-bold text-emerald-400 mb-3">
                Mapped Sources ({node.models.length})
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                {node.models.map((m) => (
                  <button
                    key={m.model_id}
                    onClick={() => onSelectModel(m.model_id, m.model)}
                    className="w-full text-left p-3 bg-emerald-900/10 border border-emerald-700/40 rounded hover:border-emerald-500 hover:bg-emerald-900/20 transition flex items-center justify-between"
                  >
                    <span className="text-gray-200 text-sm">
                      <span className="text-gray-400">{m.source_type} · {m.brand}</span> — {m.model}
                    </span>
                    <Eye className="w-4 h-4 text-gray-400" />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Child vectors (drill deeper) */}
          {children.length > 0 ? (
            <div>
              {node && (
                <h3 className="text-lg font-bold text-blue-400 mb-3">
                  {children[0] ? levelLabel(children[0].level) : 'Children'} ({children.length})
                </h3>
              )}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {children.map((v) => <VectorCard key={v.id} vec={v} onOpen={openVector} />)}
              </div>
            </div>
          ) : (
            node && (!node.models || node.models.length === 0) && (
              <p className="text-gray-400 text-sm">
                This is a leaf {levelLabel(node.level, false).toLowerCase()} with no mapped sources yet.
              </p>
            )
          )}
        </div>
      )}
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
      const res = await api.importCorrelationRulesCSV(modelId, file);
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

  const handleDeleteArtifact = async (kind, id, name) => {
    if (!window.confirm(`Delete ${kind} "${name}"? This cannot be undone.`)) return;
    try {
      if (kind === 'parser') await api.deleteParser(id);
      else if (kind === 'correlation rule') await api.deleteCorrelationRule(id);
      else if (kind === 'SOAR flow') await api.deleteSOARFlow(id);
      else if (kind === 'highlight') await api.deleteHighlight(id);
      showToast(`${kind.charAt(0).toUpperCase() + kind.slice(1)} deleted.`, 'success');
      await refreshDetails();
    } catch (err) {
      showToast(`Failed to delete ${kind}: ${err.message}`, 'error');
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

            {/* Mapped framework TTPs */}
            <div className="mt-8">
              <h3 className="text-lg font-bold text-white mb-3">Mapped Framework TTPs</h3>
              {details.framework_vectors && details.framework_vectors.length > 0 ? (
                ['mitre', 'nist'].map((fw) => {
                  const items = details.framework_vectors.filter((v) => v.framework === fw);
                  if (!items.length) return null;
                  return (
                    <div key={fw} className="mb-3">
                      <div className="text-xs uppercase tracking-wide text-gray-400 mb-2">
                        {fw === 'mitre' ? 'MITRE ATT&CK' : 'NIST CSF 2.0'} ({items.length})
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {items.map((v) => (
                          <span
                            key={v.map_id}
                            title={v.name}
                            className={`text-xs px-2 py-1 rounded ${fw === 'mitre' ? 'bg-red-500/15 text-red-200' : 'bg-indigo-500/15 text-indigo-200'}`}
                          >
                            <span className="font-mono">{v.external_id}</span>
                            <span className="text-gray-400 ml-1.5 capitalize">{v.level}</span>
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })
              ) : (
                <p className="text-gray-400 text-sm">
                  No TTPs mapped. {canEdit ? 'Use “Manage Sources” to map this model to MITRE/NIST TTPs.' : ''}
                </p>
              )}
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
                    <div className="flex items-center gap-2">
                      <span className={`text-xs px-2 py-1 rounded ${
                        rule.severity === 'critical' ? 'bg-red-500/20 text-red-300' :
                        rule.severity === 'high' ? 'bg-orange-500/20 text-orange-300' :
                        rule.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-300' :
                        'bg-blue-500/20 text-blue-300'
                      }`}>
                        {rule.severity}
                      </span>
                      {canEdit && (
                        <button
                          onClick={() => handleDeleteArtifact('correlation rule', rule.id, rule.name)}
                          className="text-red-400 hover:text-red-300"
                          title="Delete rule"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
                  </div>
                  <p className="text-sm text-gray-400 mb-2">{rule.description}</p>
                  <div className="mt-2 mb-3 text-xs font-mono text-gray-300 bg-slate-800 p-2 rounded overflow-x-auto whitespace-pre-wrap">
                    {typeof rule.rule_logic === 'string'
                      ? rule.rule_logic
                      : JSON.stringify(rule.rule_logic, null, 2)}
                  </div>
                  {Array.isArray(rule.tags) && rule.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mb-2">
                      {rule.tags.map((tag, ti) => (
                        <span key={ti} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-600/60 text-slate-300 font-mono">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
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
                    <div className="flex items-center gap-2">
                      <span className="text-xs bg-blue-500/20 text-blue-300 px-2 py-1 rounded">
                        {parser.format.toUpperCase()}
                      </span>
                      {canEdit && (
                        <button
                          onClick={() => handleDeleteArtifact('parser', parser.id, parser.name)}
                          className="text-red-400 hover:text-red-300"
                          title="Delete parser"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      )}
                    </div>
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
                  <div className="flex items-start justify-between mb-2">
                    <h4 className="font-semibold text-white">{flow.name}</h4>
                    {canEdit && (
                      <button
                        onClick={() => handleDeleteArtifact('SOAR flow', flow.id, flow.name)}
                        className="text-red-400 hover:text-red-300"
                        title="Delete SOAR flow"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
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
                <div key={h.id ?? i} className={`p-4 rounded border-l-4 ${
                  h.priority === 'critical' ? 'bg-red-900/20 border-red-500' :
                  h.priority === 'high' ? 'bg-orange-900/20 border-orange-500' :
                  h.priority === 'medium' ? 'bg-yellow-900/20 border-yellow-500' :
                  'bg-blue-900/20 border-blue-500'
                }`}>
                  <div className="flex items-start justify-between">
                    <h4 className="font-bold text-white">{h.title}</h4>
                    {canEdit && h.id != null && (
                      <button
                        onClick={() => handleDeleteArtifact('highlight', h.id, h.title)}
                        className="text-red-400 hover:text-red-300"
                        title="Delete highlight"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    )}
                  </div>
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
  });
  const [configText, setConfigText] = useState('{\n  \n}');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    let parser_config;
    try {
      parser_config = configText.trim() ? JSON.parse(configText) : {};
    } catch (err) {
      setError('Parser config must be valid JSON.');
      return;
    }
    try {
      await api.createParser(modelId, { ...formData, parser_config });
      onClose();
      if (onSuccess) onSuccess();
    } catch (err) {
      setError(err.message || 'Failed to create parser');
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
        {['kv', 'json', 'grok', 'csv', 'cef', 'xml', 'syslog_grok'].map((fmt) => (
          <option key={fmt} value={fmt}>
            {fmt.toUpperCase()}
          </option>
        ))}
      </select>
      <textarea
        placeholder="Description"
        value={formData.description}
        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 h-16"
      />
      <label className="block text-xs text-gray-300 mb-1">Parser Config (JSON)</label>
      <textarea
        value={configText}
        onChange={(e) => setConfigText(e.target.value)}
        className="w-full px-3 py-2 bg-slate-800 border border-slate-500 rounded text-white mb-2 h-28 font-mono text-xs"
        spellCheck={false}
      />
      {error && (
        <div className="mb-2 text-red-300 text-xs bg-red-500/10 border border-red-500/40 rounded px-2 py-1">{error}</div>
      )}
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
    severity: 'medium',
  });
  const [tagsText, setTagsText] = useState('');
  const [error, setError] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    // Accept either a JSON object or a plain expression string for rule_logic.
    let rule_logic = formData.rule_logic;
    const trimmed = formData.rule_logic.trim();
    if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
      try {
        rule_logic = JSON.parse(trimmed);
      } catch {
        rule_logic = formData.rule_logic; // keep as raw expression
      }
    }
    const tags = tagsText.split(',').map((t) => t.trim()).filter(Boolean);
    try {
      await api.createCorrelationRule(modelId, { ...formData, rule_logic, tags });
      onClose();
      if (onSuccess) onSuccess();
    } catch (err) {
      setError(err.message || 'Failed to create rule');
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
      <textarea
        placeholder="Description (optional)"
        value={formData.description}
        onChange={(e) => setFormData({ ...formData, description: e.target.value })}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 h-16"
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
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 h-20 font-mono text-xs"
        required
      />
      <input
        type="text"
        placeholder="Tags (comma-separated, e.g. TA0001, T1078)"
        value={tagsText}
        onChange={(e) => setTagsText(e.target.value)}
        className="w-full px-3 py-2 bg-slate-600 border border-slate-500 rounded text-white mb-2 text-sm"
      />
      {error && (
        <div className="mb-2 text-red-300 text-xs bg-red-500/10 border border-red-500/40 rounded px-2 py-1">{error}</div>
      )}
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
// SOURCE MANAGEMENT (admin / super_admin) — types, brands, models + TTP mapping
// ============================================================================

function SourceManagement() {
  const [types, setTypes] = useState([]);
  const [brands, setBrands] = useState([]);
  const [models, setModels] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [mappingModel, setMappingModel] = useState(null);

  const [typeForm, setTypeForm] = useState({ name: '', description: '' });
  const [brandForm, setBrandForm] = useState({ name: '', description: '' });
  const [modelForm, setModelForm] = useState({ source_type_id: '', brand_id: '', name: '', description: '' });

  const load = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [t, b, m] = await Promise.all([api.getSourceTypes(), api.getBrands(), api.getSourceModels()]);
      setTypes(t); setBrands(b); setModels(m);
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);

  const flash = (msg) => { setNotice(msg); setError(''); setTimeout(() => setNotice(''), 4000); };
  const fail = (msg) => { setError(msg); };

  const submitType = async (e) => {
    e.preventDefault();
    try { await api.createSourceType(typeForm); setTypeForm({ name: '', description: '' }); flash('Source type created.'); await load(); }
    catch (err) { fail(err.message); }
  };
  const submitBrand = async (e) => {
    e.preventDefault();
    try { await api.createBrand(brandForm); setBrandForm({ name: '', description: '' }); flash('Brand created.'); await load(); }
    catch (err) { fail(err.message); }
  };
  const submitModel = async (e) => {
    e.preventDefault();
    if (!modelForm.source_type_id || !modelForm.brand_id) { fail('Pick a source type and brand.'); return; }
    try {
      await api.createSourceModel({
        ...modelForm,
        source_type_id: Number(modelForm.source_type_id),
        brand_id: Number(modelForm.brand_id),
      });
      setModelForm({ source_type_id: '', brand_id: '', name: '', description: '' });
      flash('Source model created.');
      await load();
    } catch (err) { fail(err.message); }
  };

  const del = async (kind, fn, id, name) => {
    if (!window.confirm(`Delete ${kind} "${name}"? This cannot be undone.`)) return;
    try { await fn(id); flash(`${kind} deleted.`); await load(); }
    catch (err) { fail(err.message); }
  };

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">Manage Sources</h2>
      {error && <div className="mb-4 bg-red-500/10 border border-red-500/50 text-red-300 px-4 py-2 rounded text-sm">{error}</div>}
      {notice && <div className="mb-4 bg-green-500/10 border border-green-500/50 text-green-300 px-4 py-2 rounded text-sm">{notice}</div>}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        {/* Source Types */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
          <h3 className="text-lg font-semibold text-white mb-3">Source Types</h3>
          <form onSubmit={submitType} className="flex gap-2 mb-3">
            <input value={typeForm.name} onChange={(e) => setTypeForm({ ...typeForm, name: e.target.value })}
              placeholder="e.g. WAF" required className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
            <input value={typeForm.description} onChange={(e) => setTypeForm({ ...typeForm, description: e.target.value })}
              placeholder="description" className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
            <button className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white text-sm flex items-center gap-1"><Plus className="w-4 h-4" /></button>
          </form>
          <div className="flex flex-wrap gap-2">
            {types.map((t) => (
              <span key={t.id} className="flex items-center gap-1 text-xs bg-slate-700 px-2 py-1 rounded text-gray-200">
                {t.name}
                <button onClick={() => del('source type', api.deleteSourceType.bind(api), t.id, t.name)} className="text-red-400 hover:text-red-300"><Trash2 className="w-3 h-3" /></button>
              </span>
            ))}
          </div>
        </div>

        {/* Brands */}
        <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5">
          <h3 className="text-lg font-semibold text-white mb-3">Brands</h3>
          <form onSubmit={submitBrand} className="flex gap-2 mb-3">
            <input value={brandForm.name} onChange={(e) => setBrandForm({ ...brandForm, name: e.target.value })}
              placeholder="e.g. Imperva" required className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
            <input value={brandForm.description} onChange={(e) => setBrandForm({ ...brandForm, description: e.target.value })}
              placeholder="description" className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
            <button className="px-3 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white text-sm flex items-center gap-1"><Plus className="w-4 h-4" /></button>
          </form>
          <div className="flex flex-wrap gap-2">
            {brands.map((b) => (
              <span key={b.id} className="flex items-center gap-1 text-xs bg-slate-700 px-2 py-1 rounded text-gray-200">
                {b.name}
                <button onClick={() => del('brand', api.deleteBrand.bind(api), b.id, b.name)} className="text-red-400 hover:text-red-300"><Trash2 className="w-3 h-3" /></button>
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Create model */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-5 mb-8">
        <h3 className="text-lg font-semibold text-white mb-3 flex items-center gap-2"><Plus className="w-5 h-5 text-blue-400" /> Add Source Model</h3>
        <form onSubmit={submitModel} className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <select value={modelForm.source_type_id} onChange={(e) => setModelForm({ ...modelForm, source_type_id: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm">
            <option value="">Source Type…</option>
            {types.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
          <select value={modelForm.brand_id} onChange={(e) => setModelForm({ ...modelForm, brand_id: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm">
            <option value="">Brand…</option>
            {brands.map((b) => <option key={b.id} value={b.id}>{b.name}</option>)}
          </select>
          <input value={modelForm.name} onChange={(e) => setModelForm({ ...modelForm, name: e.target.value })}
            placeholder="Model name" required className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
          <input value={modelForm.description} onChange={(e) => setModelForm({ ...modelForm, description: e.target.value })}
            placeholder="description" className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
          <button className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded text-sm">Create</button>
        </form>
      </div>

      {/* Models list */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-700 text-white font-semibold">Source Models ({models.length})</div>
        {loading ? (
          <p className="text-gray-400 p-6">Loading…</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-700/50 text-gray-300">
              <tr>
                <th className="text-left px-4 py-3">Model</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">Brand</th>
                <th className="text-left px-4 py-3">Mapped TTPs</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {models.map((m) => (
                <tr key={m.id} className="border-t border-slate-700 text-gray-200">
                  <td className="px-4 py-3 font-medium">{m.name}</td>
                  <td className="px-4 py-3 text-gray-400">{m.source_type}</td>
                  <td className="px-4 py-3 text-gray-400">{m.brand}</td>
                  <td className="px-4 py-3">
                    <span className={m.mapped_vectors ? 'text-blue-300' : 'text-gray-500'}>{m.mapped_vectors}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center justify-end gap-2">
                      <button onClick={() => setMappingModel(m)}
                        className="px-3 py-1 bg-blue-600/80 hover:bg-blue-600 rounded text-xs transition">Map TTPs</button>
                      <button onClick={() => del('source model', api.deleteSourceModel.bind(api), m.id, m.name)}
                        className="px-3 py-1 bg-red-600/80 hover:bg-red-600 rounded text-xs transition flex items-center gap-1"><Trash2 className="w-3 h-3" /> Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
              {models.length === 0 && (
                <tr><td colSpan={5} className="px-4 py-6 text-gray-400 text-center">No source models yet. Add one above.</td></tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {mappingModel && (
        <VectorMappingModal
          model={mappingModel}
          onClose={() => setMappingModel(null)}
          onChanged={load}
        />
      )}
    </div>
  );
}

// Modal: search MITRE / NIST and map one or many TTPs to a source model.
function VectorMappingModal({ model, onClose, onChanged }) {
  const [current, setCurrent] = useState([]);
  const [framework, setFramework] = useState('mitre');
  const [q, setQ] = useState('');
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const loadCurrent = useCallback(async () => {
    try { setCurrent(await api.getModelVectors(model.id)); }
    catch (err) { setError(err.message); }
    setLoading(false);
  }, [model.id]);

  useEffect(() => { loadCurrent(); }, [loadCurrent]);

  const search = async (e) => {
    e.preventDefault();
    setError('');
    try { setResults(await api.searchVectors(framework, q.trim())); }
    catch (err) { setError(err.message); }
  };

  const mappedIds = new Set(current.map((c) => c.vector_id));

  const add = async (vec) => {
    setBusy(true); setError('');
    try { await api.mapModelVectors(model.id, [vec.id]); await loadCurrent(); onChanged && onChanged(); }
    catch (err) { setError(err.message); }
    setBusy(false);
  };
  const remove = async (vectorId) => {
    setBusy(true); setError('');
    try { await api.unmapModelVector(model.id, vectorId); await loadCurrent(); onChanged && onChanged(); }
    catch (err) { setError(err.message); }
    setBusy(false);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-slate-900 border border-slate-700 rounded-lg w-full max-w-3xl max-h-[85vh] flex flex-col" onClick={(e) => e.stopPropagation()}>
        <div className="px-5 py-3 border-b border-slate-700 flex items-center justify-between">
          <div>
            <div className="text-white font-semibold">Map TTPs — {model.name}</div>
            <div className="text-xs text-gray-400">{model.source_type} · {model.brand}</div>
          </div>
          <button onClick={onClose} className="text-gray-400 hover:text-white font-mono">✕</button>
        </div>

        <div className="p-5 overflow-y-auto">
          {error && <div className="mb-3 bg-red-500/10 border border-red-500/50 text-red-300 px-3 py-2 rounded text-xs">{error}</div>}

          {/* Current mappings */}
          <div className="mb-4">
            <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Currently mapped ({current.length})</div>
            {loading ? <p className="text-gray-400 text-sm">Loading…</p> : current.length === 0 ? (
              <p className="text-gray-500 text-sm italic">No TTPs mapped yet.</p>
            ) : (
              <div className="flex flex-wrap gap-2">
                {current.map((c) => (
                  <span key={c.map_id} className={`flex items-center gap-1 text-xs px-2 py-1 rounded ${c.framework === 'mitre' ? 'bg-red-500/15 text-red-200' : 'bg-indigo-500/15 text-indigo-200'}`}>
                    <span className="font-mono">{c.external_id}</span>
                    <span className="text-gray-400 hidden sm:inline">{c.name?.slice(0, 28)}</span>
                    <button disabled={busy} onClick={() => remove(c.vector_id)} className="text-red-300 hover:text-red-100 ml-1">✕</button>
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Search & add */}
          <div className="border-t border-slate-700 pt-4">
            <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Add TTPs</div>
            <form onSubmit={search} className="flex gap-2 mb-3">
              <select value={framework} onChange={(e) => { setFramework(e.target.value); setResults([]); }}
                className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm">
                <option value="mitre">MITRE</option>
                <option value="nist">NIST</option>
              </select>
              <input value={q} onChange={(e) => setQ(e.target.value)}
                placeholder={framework === 'mitre' ? 'e.g. T1059, PowerShell, TA0005' : 'e.g. DE.CM, detect'}
                className="flex-1 px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm" />
              <button className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm">Search</button>
            </form>
            <div className="space-y-1 max-h-64 overflow-y-auto">
              {results.map((v) => {
                const isMapped = mappedIds.has(v.id);
                return (
                  <div key={v.id} className="flex items-center justify-between gap-2 p-2 bg-slate-800 rounded">
                    <div className="min-w-0">
                      <span className="font-mono text-blue-300 text-xs">{v.external_id}</span>
                      <span className="text-gray-300 text-sm ml-2">{v.name}</span>
                      <span className="text-[10px] text-gray-500 ml-2 capitalize">{v.level}</span>
                    </div>
                    <button disabled={busy || isMapped} onClick={() => add(v)}
                      className={`px-2 py-1 rounded text-xs flex-shrink-0 ${isMapped ? 'bg-slate-700 text-gray-500 cursor-default' : 'bg-emerald-600 hover:bg-emerald-700 text-white'}`}>
                      {isMapped ? 'Mapped' : 'Add'}
                    </button>
                  </div>
                );
              })}
              {results.length === 0 && <p className="text-gray-500 text-xs">Search to find TTPs to map.</p>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ============================================================================
// USER MANAGEMENT (admin / super_admin)
// ============================================================================

function UserManagement({ userRole, currentUsername }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState({ username: '', email: '', password: '', role: 'analyst' });
  const [submitting, setSubmitting] = useState(false);

  // Roles this actor is allowed to assign (mirrors backend rules).
  const assignableRoles = userRole === 'super_admin'
    ? ['analyst', 'admin', 'super_admin']
    : ['analyst', 'admin'];

  const canManage = (target) => {
    if (userRole === 'super_admin') return true;
    return target.role !== 'super_admin';
  };

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      setUsers(await api.getUsers());
    } catch (err) {
      setError(err.message);
    }
    setLoading(false);
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError('');
    setNotice('');
    try {
      await api.createUser(form);
      setNotice(`User "${form.username}" created.`);
      setForm({ username: '', email: '', password: '', role: 'analyst' });
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
    setSubmitting(false);
  };

  const handleDelete = async (user) => {
    if (!window.confirm(`Delete user "${user.username}"? This cannot be undone.`)) return;
    setError('');
    setNotice('');
    try {
      await api.deleteUser(user.id);
      setNotice(`User "${user.username}" deleted.`);
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  const handleToggleActive = async (user) => {
    setError('');
    setNotice('');
    try {
      await api.updateUser(user.id, { is_active: !user.is_active });
      await loadUsers();
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div>
      <h2 className="text-2xl font-bold text-white mb-6">User Management</h2>

      {error && (
        <div className="mb-4 bg-red-500/10 border border-red-500/50 text-red-300 px-4 py-2 rounded text-sm">{error}</div>
      )}
      {notice && (
        <div className="mb-4 bg-green-500/10 border border-green-500/50 text-green-300 px-4 py-2 rounded text-sm">{notice}</div>
      )}

      {/* Create user */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg p-6 mb-8">
        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
          <Plus className="w-5 h-5 text-blue-400" /> Create User
        </h3>
        <form onSubmit={handleCreate} className="grid grid-cols-1 md:grid-cols-5 gap-3">
          <input
            required
            value={form.username}
            onChange={(e) => setForm({ ...form, username: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
            placeholder="Username"
            autoComplete="off"
          />
          <input
            required
            type="email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
            placeholder="Email"
            autoComplete="off"
          />
          <input
            required
            type="password"
            minLength={8}
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
            placeholder="Password (min 8)"
            autoComplete="new-password"
          />
          <select
            value={form.role}
            onChange={(e) => setForm({ ...form, role: e.target.value })}
            className="px-3 py-2 bg-slate-700 border border-slate-600 rounded text-white text-sm"
          >
            {assignableRoles.map((r) => (
              <option key={r} value={r}>{r}</option>
            ))}
          </select>
          <button
            type="submit"
            disabled={submitting}
            className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-2 px-4 rounded text-sm transition disabled:opacity-50"
          >
            {submitting ? 'Creating…' : 'Create'}
          </button>
        </form>
      </div>

      {/* User list */}
      <div className="bg-slate-800/50 border border-slate-700 rounded-lg overflow-hidden">
        {loading ? (
          <p className="text-gray-400 p-6">Loading users…</p>
        ) : (
          <table className="w-full text-sm">
            <thead className="bg-slate-700/50 text-gray-300">
              <tr>
                <th className="text-left px-4 py-3">Username</th>
                <th className="text-left px-4 py-3">Email</th>
                <th className="text-left px-4 py-3">Role</th>
                <th className="text-left px-4 py-3">Status</th>
                <th className="text-right px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => {
                const isSelf = u.username === currentUsername;
                const manageable = canManage(u) && !isSelf;
                return (
                  <tr key={u.id} className="border-t border-slate-700 text-gray-200">
                    <td className="px-4 py-3 font-medium">
                      {u.username}{isSelf && <span className="ml-2 text-xs text-blue-400">(you)</span>}
                    </td>
                    <td className="px-4 py-3 text-gray-400">{u.email}</td>
                    <td className="px-4 py-3 capitalize">{u.role.replace('_', ' ')}</td>
                    <td className="px-4 py-3">
                      <span className={u.is_active ? 'text-green-400' : 'text-gray-500'}>
                        {u.is_active ? 'Active' : 'Inactive'}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => handleToggleActive(u)}
                          disabled={!manageable}
                          className="px-3 py-1 bg-slate-700 hover:bg-slate-600 rounded text-xs transition disabled:opacity-30 disabled:cursor-not-allowed"
                        >
                          {u.is_active ? 'Deactivate' : 'Activate'}
                        </button>
                        <button
                          onClick={() => handleDelete(u)}
                          disabled={!manageable}
                          className="px-3 py-1 bg-red-600/80 hover:bg-red-600 rounded text-xs transition disabled:opacity-30 disabled:cursor-not-allowed flex items-center gap-1"
                        >
                          <Trash2 className="w-3 h-3" /> Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

// ============================================================================
// MAIN APP
// ============================================================================

export default function App() {
  const [isLoggedIn, setIsLoggedIn] = useState(!!localStorage.getItem('auth_token'));
  const [userRole, setUserRole] = useState(localStorage.getItem('user_role') || 'analyst');
  const [username, setUsername] = useState(localStorage.getItem('username') || '');
  const [currentPage, setCurrentPage] = useState('frameworks');
  const [selectedFramework, setSelectedFramework] = useState(null);
  const [selectedVector, setSelectedVector] = useState(null);
  const [selectedVectorName, setSelectedVectorName] = useState(null);
  const [selectedModel, setSelectedModel] = useState(null);
  const [selectedModelName, setSelectedModelName] = useState(null);

  const handleLogin = (role, uname) => {
    setIsLoggedIn(true);
    setUserRole(role);
    setUsername(uname || '');
    localStorage.setItem('auth_token', api.token);
    localStorage.setItem('user_role', role);
    localStorage.setItem('username', uname || '');
  };

  const handleLogout = () => {
    setIsLoggedIn(false);
    localStorage.removeItem('auth_token');
    localStorage.removeItem('user_role');
    localStorage.removeItem('username');
    api.token = null;
    setCurrentPage('frameworks');
  };

  const isAdmin = ['admin', 'super_admin'].includes(userRole);

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
            <button
              onClick={() => setCurrentPage('frameworks')}
              className={`px-3 py-2 rounded text-sm transition ${!['users', 'sources'].includes(currentPage) ? 'text-blue-400 font-semibold' : 'text-gray-300 hover:text-white'}`}
            >
              Dashboard
            </button>
            {isAdmin && (
              <button
                onClick={() => setCurrentPage('sources')}
                className={`px-3 py-2 rounded text-sm transition ${currentPage === 'sources' ? 'text-blue-400 font-semibold' : 'text-gray-300 hover:text-white'}`}
              >
                Manage Sources
              </button>
            )}
            {isAdmin && (
              <button
                onClick={() => setCurrentPage('users')}
                className={`px-3 py-2 rounded text-sm transition ${currentPage === 'users' ? 'text-blue-400 font-semibold' : 'text-gray-300 hover:text-white'}`}
              >
                Users
              </button>
            )}
            <span className="text-gray-400 text-sm">
              {username && <span className="text-gray-300">{username} · </span>}
              <span className="font-semibold text-blue-400 capitalize">{userRole.replace('_', ' ')}</span>
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
        {currentPage === 'users' && isAdmin && (
          <UserManagement userRole={userRole} currentUsername={username} />
        )}

        {currentPage === 'sources' && isAdmin && (
          <SourceManagement />
        )}

        {currentPage === 'frameworks' && (
          <FrameworkSelector
            onSelectFramework={(fw) => {
              setSelectedFramework(fw);
              setCurrentPage('explore');
            }}
          />
        )}

        {currentPage === 'explore' && selectedFramework && (
          <VectorExplorer
            framework={selectedFramework}
            onSelectModel={(id, name) => {
              setSelectedModel(id);
              setSelectedModelName(name);
              setCurrentPage('detail');
            }}
            onBack={() => {
              setCurrentPage('frameworks');
              setSelectedFramework(null);
            }}
          />
        )}

        {currentPage === 'detail' && selectedModel && (
          <ModelDetail
            modelId={selectedModel}
            modelName={selectedModelName}
            userRole={userRole}
            onBack={() => setCurrentPage('explore')}
          />
        )}
      </main>
    </div>
  );
}
