export interface Scan {
  id: string;
  target_url: string;
  status: "pending" | "running" | "completed" | "failed" | "cancelled";
  score: number | null;
  rating: string | null;
  started_at: string | null;
  completed_at: string | null;
  findings_count: number;
  user_id: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  scanner: string;
  category: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  confidence: "high" | "medium" | "low";
  evidence: Record<string, unknown> | null;
  recommendation: string | null;
  score_impact: number;
  created_at: string;
}

export interface ScanDetail extends Scan {
  findings: Finding[];
}

export interface ScanProgress {
  scan_id: string;
  status: string;
  progress: number;
  current_scanner: string | null;
  findings_so_far: number;
  estimated_remaining_seconds: number | null;
}

export interface ScoreBreakdown {
  category: string;
  score: number;
  max_score: number;
  findings_count: number;
}

export interface ScanReport {
  scan: ScanDetail;
  score_breakdown: ScoreBreakdown[];
  summary: Record<string, number>;
  risk_level: string;
}

export interface ScanListResponse {
  items: Scan[];
  total: number;
  page: number;
  page_size: number;
}

export interface ScanStats {
  total_scans: number;
  completed_scans: number;
  failed_scans: number;
  average_score: number | null;
  rating_distribution: Record<string, number>;
  recent_scans: Scan[];
}

export interface User {
  id: string;
  email: string;
  is_active: boolean;
  is_superuser: boolean;
  created_at: string;
  updated_at: string;
}
