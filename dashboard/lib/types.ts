// Mirrors the Risk Certificate contract in backend/app/certificate.py.
// Field names must not change: the backend signs exactly this shape.

export type Verdict = "AUTO_APPROVED" | "BLOCKED_PENDING_REVIEW";
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type Action = "create" | "update" | "delete" | "replace" | "no-op";
export type Pillar = "security" | "reliability" | "cost" | "performance";
export const PILLARS: Pillar[] = ["security", "reliability", "cost", "performance"];

export interface ResourceChange {
  resource: string;
  action: Action;
  before: Record<string, unknown> | null;
  after: Record<string, unknown> | null;
}

export interface ConfigChange {
  // catalog architectures: a service field; plain Terraform: a resource attribute
  service?: string;
  type?: string;
  field?: string;
  from?: unknown;
  resource?: string;
  attribute?: string;
  to: unknown;
}

export interface Remediation {
  summary: string;
  config_change: ConfigChange[];
  generated_by: "groq" | "template";
}

export interface RiskFlag {
  rule: string;
  severity: Severity;
  resource: string;
  message: string;
  pillar?: Pillar; // added later; absent on older certificates (= security)
  remediation?: Remediation; // added later; absent on older certificates
}

// score = max(0, 100 - sum of penalties); penalty CRITICAL 40, HIGH 25, MEDIUM 10, LOW 5
export interface PillarScore {
  score: number;
  findings: { rule: string; severity: Severity; resource: string; penalty: number }[];
}

export type Pillars = Record<Pillar, PillarScore>;

export interface CostBreakdownRow {
  resource: string;
  type: string | null;
  action: string | null;
  monthly_usd: number | null;
  delta_usd: number | null;
  usage_assumptions: Record<string, number>;
  note: string | null;
}

export interface ShadowInventoryItem {
  type: string;
  id: string;
  name?: string;
}

export interface NewlyPublic {
  address: string;
  type: string;
  via: string[];
}

export interface IamWidened {
  address: string;
  type: string;
  added_grants: { action: string; resource: string }[];
  removed_denies: { action: string; resource: string }[];
  admin: boolean;
  unknown: boolean;
}

export interface GraphNode {
  id: string;
  type: string;
  action: Action;
  risk: boolean;
  risk_reasons: string[];
}

export interface GraphEdge {
  source: string;
  target: string;
  via: string[];
}

export interface Certificate {
  plan_id: string;
  timestamp: string;
  resource_changes: ResourceChange[];
  blast_radius: {
    newly_public: NewlyPublic[];
    iam_widened: IamWidened[];
    risk_flags: RiskFlag[];
    graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  };
  shadow_run: {
    applied: boolean;
    resources_created: number;
    error: string | null;
    resources?: ShadowInventoryItem[]; // boto3 inventory of MiniStack before teardown
    inventory_error?: string | null;
  };
  cost_delta: { monthly_usd: number | null; note: string | null };
  verdict: Verdict;
  risk_explanation: string;
  generated_by: "groq" | "template";
  cost_breakdown?: CostBreakdownRow[];
  generated_terraform?: string | null;
  architecture?: { services: (ArchitectureServiceInfo & { analysis: "shadow_and_static" | "static_only" })[] } | null;
  pillars?: Pillars; // added later; absent on older certificates
  signature_alg?: SignatureAlg; // absent on older certificates, which are HMAC-SHA256
  signature: string;
}

// ed25519: anyone can verify with GET /public-key; hmac-sha256: only holders of the secret.
export type SignatureAlg = "ed25519" | "hmac-sha256";

// --- service catalog & architecture builder ------------------------------------------------

export type FieldKind = "select" | "int" | "bool" | "cidr" | "string" | "list";

export interface CatalogField {
  name: string;
  label: string;
  kind: FieldKind;
  default: unknown;
  options?: (string | number)[];
  min?: number;
  max?: number;
  pattern?: string;
  item_pattern?: string;
  help?: string;
  infracost_key?: string;
}

export interface CatalogService {
  type: string;
  label: string;
  description: string;
  resources: string[];
  shadow_supported: boolean;
  pricing: "fixed" | "usage_based" | "free" | "unsupported";
  pricing_note: string;
  fields: CatalogField[];
  usage_fields?: CatalogField[];
}

export interface ArchitectureService {
  type: string;
  config: Record<string, unknown>;
  usage?: Record<string, unknown>;
}

export interface ArchitectureServiceInfo {
  type: string;
  name: string;
  shadow_supported: boolean;
  config: Record<string, unknown>;
  usage: Record<string, unknown>;
  resources?: string[];
}

export interface ArchitectureError {
  service: number | "-";
  field: string;
  message: string;
}

export interface PreviewResult {
  terraform: string;
  filename: string;
  resources: string[];
  services: ArchitectureServiceInfo[];
}

export interface CheckResult {
  verdict_preview: Verdict;
  static_only: true;
  risk_flags: RiskFlag[];
  pillars: Pillars;
  newly_public: NewlyPublic[];
  iam_widened: IamWidened[];
  graph: { nodes: GraphNode[]; edges: GraphEdge[] };
  cost_delta: { monthly_usd: number | null; note: string | null };
  cost_breakdown: CostBreakdownRow[];
  resource_count: number;
  services: ArchitectureServiceInfo[];
  generated_terraform: string;
  duration_s: number;
}

export interface Decision {
  id: number;
  plan_id: string;
  decision: "approve" | "deny";
  reviewer: string;
  comment: string | null;
  certificate_signature: string;
  verdict_at_decision: Verdict;
  decided_at: string;
}

export interface CertificateSummary {
  plan_id: string;
  timestamp: string;
  verdict: Verdict;
  generated_by: "groq" | "template";
  resource_change_count: number;
  risk_flag_counts: Record<Severity, number>;
  monthly_usd: number | null;
  shadow_applied: boolean;
  latest_decision: { decision: "approve" | "deny"; reviewer: string; decided_at: string } | null;
  // where it came from: a Builder design (with its services) or a Terraform plan
  source?: { kind: "builder" | "plan"; services: { name: string; type: string }[] };
  pillar_scores?: Record<Pillar, number> | null; // null for certificates from before pillars
  blocking_count?: number;
}

export interface VerifyResult {
  plan_id: string;
  valid: boolean;
  verdict: Verdict;
  timestamp: string;
  signature: string;
  signature_alg: SignatureAlg;
}

export const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
