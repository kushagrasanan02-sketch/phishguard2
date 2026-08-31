export type UserRole = 'USER' | 'ADMIN';

export interface User {
  id: string;
  email: string;
  full_name?: string;
  role: UserRole;
  is_active: boolean;
  created_at: string;
  last_login?: string;
}

export interface AuthState {
  user: User | null;
  token: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
}

export interface RiskFactor {
  factor: string;
  description: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  score_contribution: number;
}

export interface URLFeatures {
  url_length: number;
  hostname_length: number;
  subdomain_count: number;
  dot_count: number;
  hyphen_count: number;
  special_char_count: number;
  has_ip: boolean;
  has_at_symbol: boolean;
  has_punycode: boolean;
  parameter_count: number;
  has_suspicious_keywords: boolean;
  detected_keywords: string[];
  domain_age_days?: number;
  https_enabled: boolean;
  redirect_count: number;
  ssl_valid?: boolean;
  brand_impersonated?: string;
}

export interface ScanResult {
  id: string;
  url: string;
  normalized_url: string;
  domain: string;
  risk_score: number;
  classification: 'SAFE' | 'GUARDED' | 'SUSPICIOUS' | 'PHISHING';
  ml_probability: number;
  created_at: string;
  features?: URLFeatures;
  risk_factors: RiskFactor[];
}

export interface EmbeddedURLScan {
  url: string;
  domain: string;
  risk_score: number;
  classification: string;
}

export interface EmailScanResult {
  id: string;
  sender?: string;
  recipient?: string;
  subject?: string;
  risk_score: number;
  classification: string;
  spf_result?: string;
  dkim_result?: string;
  dmarc_result?: string;
  reply_to_mismatch: boolean;
  extracted_urls?: string[];
  url_scans?: EmbeddedURLScan[];
  indicators?: string[];
  created_at: string;
}

export interface DashboardStats {
  total_scans: number;
  phishing_detected: number;
  safe_urls: number;
  high_risk_urls: number;
  average_risk_score: number;
  threat_distribution: {
    SAFE: number;
    GUARDED: number;
    SUSPICIOUS: number;
    PHISHING: number;
  };
}

export interface ModelVersion {
  id: string;
  version: string;
  algorithm: string;
  metrics: {
    accuracy: number;
    precision: number;
    recall: number;
    f1_score: number;
    roc_auc: number;
  };
  is_active: boolean;
  training_date: string;
}

export interface AuditLog {
  id: string;
  user_id?: string;
  action: string;
  details?: Record<string, any>;
  ip_address?: string;
  timestamp: string;
}

export interface AdminStats {
  total_users: number;
  active_scans: number;
  email_scans: number;
  active_model: string;
  active_model_precision: number;
  system_status: string;
}

export interface APIKeyItem {
  id: string;
  name: string;
  key_prefix: string;
  is_active: boolean;
  created_at: string;
  last_used?: string;
}

export interface APIKeyCreatedItem extends APIKeyItem {
  api_key: string;
}

export interface BatchScanResponse {
  total_processed: number;
  safe_count: number;
  phishing_count: number;
  average_risk_score: number;
  scans: ScanResult[];
}

export interface WebhookSubscriptionItem {
  id: string;
  target_url: string;
  secret: string;
  events: string[];
  is_active: boolean;
  created_at: string;
}

export interface IOCItem {
  indicator: string;
  type: string;
  risk_score: number;
  classification: string;
  first_seen: string;
}

export interface IOCFeedResponse {
  feed_title: string;
  generated_at: string;
  total_indicators: number;
  indicators: IOCItem[];
}

