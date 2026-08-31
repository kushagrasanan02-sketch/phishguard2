import axios from 'axios';
import { User, ScanResult, DashboardStats, EmailScanResult, ModelVersion, AuditLog, AdminStats, APIKeyItem, APIKeyCreatedItem, BatchScanResponse, WebhookSubscriptionItem, IOCFeedResponse } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request Interceptor to inject JWT Access Token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('phishguard_token');
    if (token && config.headers) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor for auto 401 handling
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response && error.response.status === 401) {
      if (!error.config.url.includes('/auth/login')) {
        localStorage.removeItem('phishguard_token');
        localStorage.removeItem('phishguard_refresh_token');
      }
    }
    return Promise.reject(error);
  }
);

export const authService = {
  async register(data: { email: string; password: string; full_name?: string }): Promise<User> {
    const res = await api.post('/auth/register', data);
    return res.data;
  },

  async login(data: { username: string; password: string }): Promise<{ access_token: string; refresh_token: string }> {
    const formData = new URLSearchParams();
    formData.append('username', data.username);
    formData.append('password', data.password);

    const res = await api.post('/auth/login', formData, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    });
    return res.data;
  },

  async getCurrentUser(): Promise<User> {
    const res = await api.get('/auth/me');
    return res.data;
  },

  async getHealth(): Promise<{ status: string; database: string; version: string }> {
    const res = await api.get('/health');
    return res.data;
  }
};

export const scanService = {
  async scanUrl(url: string): Promise<ScanResult> {
    const res = await api.post('/scans/url', { url });
    return res.data;
  },

  async scanBatch(urls: string[]): Promise<BatchScanResponse> {
    const res = await api.post('/scans/batch', { urls });
    return res.data;
  },

  async getScan(id: string): Promise<ScanResult> {
    const res = await api.get(`/scans/${id}`);
    return res.data;
  },

  async getScanHistory(params?: {
    limit?: number;
    q?: string;
    classification?: string;
    min_risk?: number;
    max_risk?: number;
  }): Promise<ScanResult[]> {
    const res = await api.get('/scans', { params });
    return res.data;
  },

  async getDashboardStats(): Promise<DashboardStats> {
    const res = await api.get('/scans/dashboard/stats');
    return res.data;
  },

  getExecutiveReportUrl(id: string, format: string = 'html'): string {
    return `${API_BASE_URL}/scans/${id}/export/report?format=${format}`;
  },

  getSiemExportUrl(id: string, format: string = 'cef'): string {
    return `${API_BASE_URL}/scans/${id}/export/siem?format=${format}`;
  }
};

export const emailService = {
  async scanEmailText(raw_email: string): Promise<EmailScanResult> {
    const res = await api.post('/scans/email', { raw_email });
    return res.data;
  },

  async scanEmailFile(file: File): Promise<EmailScanResult> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await api.post('/scans/email/file', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  },

  async getEmailScans(): Promise<EmailScanResult[]> {
    const res = await api.get('/scans/email');
    return res.data;
  },

  async getEmailScan(id: string): Promise<EmailScanResult> {
    const res = await api.get(`/scans/email/${id}`);
    return res.data;
  }
};

export const adminService = {
  async getAdminStats(): Promise<AdminStats> {
    const res = await api.get('/admin/stats');
    return res.data;
  },

  async getSecurityAudit(): Promise<any> {
    const res = await api.get('/admin/security-audit');
    return res.data;
  },

  async runBenchmark(iterations: number = 10): Promise<any> {
    const res = await api.post(`/admin/benchmark?iterations=${iterations}`);
    return res.data;
  },

  async getModelVersions(): Promise<ModelVersion[]> {
    const res = await api.get('/admin/models');
    return res.data;
  },

  async retrainModel(): Promise<ModelVersion> {
    const res = await api.post('/admin/models/retrain');
    return res.data;
  },

  async activateModel(modelId: string): Promise<ModelVersion> {
    const res = await api.post(`/admin/models/${modelId}/activate`);
    return res.data;
  },

  async getUsers(): Promise<User[]> {
    const res = await api.get('/admin/users');
    return res.data;
  },

  async getAuditLogs(): Promise<AuditLog[]> {
    const res = await api.get('/admin/audit-logs');
    return res.data;
  },

  async getCertification(): Promise<any> {
    const res = await api.get('/admin/certification');
    return res.data;
  }
};

export const apiKeyService = {
  async listKeys(): Promise<APIKeyItem[]> {
    const res = await api.get('/auth/api-keys');
    return res.data;
  },

  async createKey(name: string): Promise<APIKeyCreatedItem> {
    const res = await api.post('/auth/api-keys', { name });
    return res.data;
  },

  async revokeKey(id: string): Promise<void> {
    await api.delete(`/auth/api-keys/${id}`);
  }
};

export const webhookService = {
  async listWebhooks(): Promise<WebhookSubscriptionItem[]> {
    const res = await api.get('/webhooks');
    return res.data;
  },

  async createWebhook(target_url: string, events?: string[]): Promise<WebhookSubscriptionItem> {
    const res = await api.post('/webhooks', { target_url, events });
    return res.data;
  },

  async deleteWebhook(id: string): Promise<void> {
    await api.delete(`/webhooks/${id}`);
  }
};

export const threatFeedService = {
  async getFeed(format: string = 'json', min_risk: number = 60): Promise<IOCFeedResponse> {
    const res = await api.get(`/threats/feed?format=${format}&min_risk=${min_risk}`);
    return res.data;
  },

  async getThreatMap(): Promise<any> {
    const res = await api.get('/threats/map');
    return res.data;
  },

  async getThreatGraph(): Promise<any> {
    const res = await api.get('/threats/graph');
    return res.data;
  },

  getBlocklistUrl(min_risk: number = 60): string {
    return `${API_BASE_URL}/threats/feed?format=blocklist&min_risk=${min_risk}`;
  }
};

export const chatService = {
  async analyzeQuery(query: string, scanContext?: any): Promise<any> {
    const res = await api.post('/chat/analyze', { query, scan_context: scanContext });
    return res.data;
  }
};

export const soarService = {
  async dispatchPlaybook(scan_id: string, action: string): Promise<any> {
    const res = await api.post('/soar/dispatch', { scan_id, action });
    return res.data;
  }
};



