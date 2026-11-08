const API_BASE = '/api';

/**
 * Handle API responses with proper error extraction
 */
async function handleResponse(response) {
  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}: ${response.statusText}`;
    try {
      const data = await response.json();
      if (data && data.detail) {
        errorMsg = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      }
    } catch (e) {
      // ignore
    }
    throw new Error(errorMsg);
  }
  return response.json();
}

export const api = {
  // Scans
  async getScans() {
    const res = await fetch(`${API_BASE}/scans`);
    return handleResponse(res);
  },

  async getScan(scanId) {
    const res = await fetch(`${API_BASE}/scans/${scanId}`);
    return handleResponse(res);
  },

  async deleteScan(scanId) {
    const res = await fetch(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
    return handleResponse(res);
  },

  async startScan({ file, git_url, local_path }) {
    if (file) {
      const formData = new FormData();
      formData.append('file', file);
      const res = await fetch(`${API_BASE}/scans`, {
        method: 'POST',
        body: formData,
      });
      return handleResponse(res);
    }

    const payload = {};
    if (git_url) payload.git_url = git_url;
    if (local_path) payload.local_path = local_path;

    const res = await fetch(`${API_BASE}/scans`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    return handleResponse(res);
  },

  // Artefacts
  async getArtefacts(scanId, filters = {}) {
    const query = new URLSearchParams();
    if (filters.type) query.append('type', filters.type);
    if (filters.risk_level) query.append('risk_level', filters.risk_level);
    if (filters.quantum_status) query.append('quantum_status', filters.quantum_status);
    if (filters.scanner) query.append('scanner', filters.scanner);
    if (filters.is_at_risk !== undefined && filters.is_at_risk !== '') {
      query.append('is_at_risk', filters.is_at_risk);
    }
    if (filters.limit) query.append('limit', filters.limit);
    if (filters.offset !== undefined) query.append('offset', filters.offset);

    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await fetch(`${API_BASE}/scans/${scanId}/artefacts${qs}`);
    return handleResponse(res);
  },

  // Summary & Risk Metrics
  async getSummary(scanId) {
    const res = await fetch(`${API_BASE}/scans/${scanId}/summary`);
    return handleResponse(res);
  },

  // Mosca Inequality parameters update
  async updateMosca(scanId, params) {
    const res = await fetch(`${API_BASE}/scans/${scanId}/mosca`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(params),
    });
    return handleResponse(res);
  },

  // Artefact Risk Override
  async overrideArtefact(artefactId, overrides) {
    const res = await fetch(`${API_BASE}/artefacts/${artefactId}/override`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(overrides),
    });
    return handleResponse(res);
  },

  // Catalogue
  async getCatalogue() {
    const res = await fetch(`${API_BASE}/catalogue`);
    return handleResponse(res);
  },

  // Export URLs
  getExportUrl(scanId, format) {
    return `${API_BASE}/scans/${scanId}/export?format=${format}`;
  },
};
