"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useRef, useState } from "react";
import { ArrowLeft, CheckCircle, FileText, Prohibit, Siren, ShieldCheck } from "@phosphor-icons/react";
import { ResourceGraph } from "@/components/ResourceGraph";
import { SEVERITY_STYLE, SignatureBadge, VerdictBadge } from "@/components/badges";
import { ErrorState, SkeletonBlock } from "@/components/states";
import { api } from "@/lib/api";
import { formatTimestamp, formatUsd, signatureAlgLabel } from "@/lib/format";
import { useCertificate, type CertificateDetail } from "@/lib/useCertificates";
import type { Certificate, Decision } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";
import { noFormRestore } from "@/lib/dom";

function Panel({ title, children, className = "", tone = "neutral" }: {
  title: React.ReactNode; children: React.ReactNode; className?: string; tone?: "neutral" | "alarm";
}) {
  const alarm = tone === "alarm";
  return (
    <section className={`min-w-0 overflow-hidden rounded-md border ${alarm ? "border-red-500/60 bg-red-500/[0.06]" : "border-line bg-surface"} ${className}`}>
      <h2 className={`flex items-center gap-2 border-b px-4 py-2.5 text-sm font-medium ${alarm ? "border-red-500/40 text-red-200" : "border-line text-zinc-300"}`}>
        {title}
      </h2>
      {children}
    </section>
  );
}

function VerdictBanner({ cert }: { cert: Certificate }) {
  const blocked = cert.verdict === "BLOCKED_PENDING_REVIEW";
  const flags = cert.blast_radius.risk_flags;
  const crit = flags.filter((f) => f.severity === "CRITICAL").length;
  const high = flags.filter((f) => f.severity === "HIGH").length;
  return (
    <div
      className={`flex flex-col gap-4 rounded-md border-l-4 px-5 py-5 md:flex-row md:items-center ${
        blocked ? "border border-red-500/50 border-l-red-500 bg-red-500/10" : "border border-emerald-500/40 border-l-emerald-500 bg-emerald-500/[0.07]"
      }`}
    >
      <div className={`flex h-12 w-12 shrink-0 items-center justify-center rounded-md ${blocked ? "bg-red-500/20 text-red-300" : "bg-emerald-500/15 text-emerald-300"}`}>
        {blocked ? <Prohibit size={28} weight="bold" aria-hidden="true" /> : <ShieldCheck size={28} weight="bold" aria-hidden="true" />}
      </div>
      <div className="flex flex-col gap-1">
        <h1 className={`font-mono text-xl font-semibold tracking-tight ${blocked ? "text-red-200" : "text-emerald-200"}`}>
          {blocked ? "BLOCKED PENDING REVIEW" : "AUTO-APPROVED"}
        </h1>
        <p className={`text-sm ${blocked ? "text-red-200/80" : "text-emerald-200/80"}`}>
          {blocked
            ? crit + high > 0
              ? `${crit} critical and ${high} high-severity findings. A human must approve or deny this change.`
              : "The change could not be verified, so a human must review it."
            : "No critical or high-severity findings, and the shadow apply succeeded."}
        </p>
      </div>
    </div>
  );
}

function BlastRadius({ cert }: { cert: Certificate }) {
  const { newly_public, iam_widened } = cert.blast_radius;
  const count = newly_public.length + iam_widened.length;
  if (count === 0) {
    return (
      <Panel title={<><ShieldCheck size={16} className="text-emerald-400" aria-hidden="true" /> Blast Radius</>}>
        <p className="px-4 py-4 text-sm text-zinc-400">No resource becomes reachable from the internet and no IAM permission widens.</p>
      </Panel>
    );
  }
  return (
    <Panel tone="alarm" title={<><Siren size={16} weight="fill" className="text-red-400" aria-hidden="true" /> Blast Radius: {count} Risk{count === 1 ? "" : "s"}</>}>
      <ul className="divide-y divide-red-500/20">
        {newly_public.map((p) => (
          <li key={`pub-${p.address}`} className="flex min-w-0 flex-col gap-0.5 px-4 py-3">
            <span className="break-all font-mono text-sm text-red-100" translate="no">{p.address}</span>
            <span className="text-xs text-red-200/80">
              Newly reachable from 0.0.0.0/0 via <span className="break-all font-mono" translate="no">{p.via.join(", ")}</span>
            </span>
          </li>
        ))}
        {iam_widened.map((w) => (
          <li key={`iam-${w.address}`} className="flex min-w-0 flex-col gap-0.5 px-4 py-3">
            <span className="break-all font-mono text-sm text-red-100" translate="no">{w.address}</span>
            <span className="text-xs text-red-200/80">
              {w.unknown
                ? "IAM policy only known after apply: cannot be checked"
                : w.admin
                  ? "IAM widened to full admin (Action * on Resource *)"
                  : `IAM grants ${w.added_grants.length} new permission(s)`}
            </span>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

function RiskFlags({ cert }: { cert: Certificate }) {
  const flags = cert.blast_radius.risk_flags;
  return (
    <Panel title={<>Risk Flags <span className="font-mono text-xs text-zinc-500">{flags.length}</span></>}>
      {flags.length === 0 ? (
        <p className="px-4 py-4 text-sm text-zinc-400">No policy, exposure, IAM or shadow-run findings.</p>
      ) : (
        <ul className="divide-y divide-line">
          {flags.map((f, i) => (
            <li key={`${f.rule}-${f.resource}-${i}`} className="grid grid-cols-[4px_minmax(0,1fr)] gap-x-3 px-4 py-3">
              <span className={`row-span-2 rounded-full ${SEVERITY_STYLE[f.severity].bar}`} aria-hidden="true" />
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className={`font-mono text-xs font-semibold ${SEVERITY_STYLE[f.severity].text}`}>{f.severity}</span>
                <span className="font-mono text-xs text-zinc-400" translate="no">{f.rule}</span>
                <span className="break-all font-mono text-xs text-zinc-200" translate="no">{f.resource}</span>
              </div>
              <p className="break-words text-sm leading-relaxed text-zinc-300">{f.message}</p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

function Facts({ cert }: { cert: Certificate }) {
  const { cost_delta: cost, shadow_run: shadow } = cert;
  const counts = SEVERITIES.map((s) => ({ s, n: cert.blast_radius.risk_flags.filter((f) => f.severity === s).length }));
  return (
    <Panel title="Summary">
      <dl className="divide-y divide-line text-sm">
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Monthly cost delta</dt>
          <dd className={`font-mono text-2xl font-semibold tabular-nums ${cost.monthly_usd === null ? "text-zinc-500" : "text-zinc-100"}`}>
            {formatUsd(cost.monthly_usd)}
            {cost.monthly_usd !== null && <span className="text-sm font-normal text-zinc-500"> /month</span>}
          </dd>
          {cost.note && <p className="break-words text-xs leading-relaxed text-zinc-500">{cost.note}</p>}
        </div>
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Shadow run on MiniStack</dt>
          <dd className={shadow.applied ? "text-emerald-300" : "text-red-300"}>
            {shadow.applied ? `Applied: ${shadow.resources_created} resources created` : "Not applied"}
          </dd>
          {shadow.error && <pre className="whitespace-pre-wrap break-words font-mono text-xs text-red-200/80">{shadow.error}</pre>}
        </div>
        <div className="flex flex-col gap-2 px-4 py-3">
          <dt className="text-xs text-zinc-500">Findings by severity</dt>
          <dd className="grid grid-cols-4 gap-2">
            {counts.map(({ s, n }) => (
              <div key={s} className="flex flex-col">
                <span className={`font-mono text-lg tabular-nums ${n ? SEVERITY_STYLE[s].text : "text-zinc-600"}`}>{n}</span>
                <span className="text-[11px] text-zinc-500">{s.toLowerCase()}</span>
              </div>
            ))}
          </dd>
        </div>
        <div className="flex flex-col gap-1 px-4 py-3">
          <dt className="text-xs text-zinc-500">Changes</dt>
          <dd className="text-zinc-200">{cert.resource_changes.length} resource change{cert.resource_changes.length === 1 ? "" : "s"}</dd>
        </div>
      </dl>
    </Panel>
  );
}

function DecisionPanel({ detail, demo, onDecided }: { detail: CertificateDetail; demo: boolean; onDecided: (d: Decision) => void }) {
  const { cert, verify, decisions } = detail;
  const [reviewer, setReviewer] = useState("");
  const [comment, setComment] = useState("");
  const [pending, setPending] = useState<"approve" | "deny" | null>(null); // awaiting confirmation
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reviewerRef = useRef<HTMLInputElement>(null);
  const blocked = cert.verdict === "BLOCKED_PENDING_REVIEW";
  const invalid = verify !== null && !verify.valid;
  const disabled = demo || invalid || busy;

  function request(decision: "approve" | "deny") {
    if (!reviewer.trim()) {
      setError("Enter your name as the reviewer, then choose Approve or Deny.");
      reviewerRef.current?.focus();
      return;
    }
    setError(null);
    setPending(decision); // decisions are permanent (append-only log): ask once more
  }

  async function confirm() {
    if (!pending) return;
    setBusy(true);
    setError(null);
    try {
      onDecided(await api.decide(cert.plan_id, pending, reviewer.trim(), comment.trim()));
      setComment("");
      setPending(null);
    } catch (err) {
      setError(`${err instanceof Error ? err.message : String(err)}. Check the API is running and try again.`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Panel title="Review">
      {blocked && (
        <div className="flex flex-col gap-3 px-4 py-4">
          {demo && <p className="text-xs text-amber-300/90">Decisions need the live API. Demo mode is read-only.</p>}
          {invalid && <p className="text-xs text-red-300">The signature is invalid, so decisions are disabled.</p>}
          <div className="flex flex-col gap-1.5">
            <label htmlFor="reviewer" className="text-xs text-zinc-400">Reviewer</label>
            <input
              id="reviewer"
              name="reviewer"
              ref={reviewerRef}
              value={reviewer}
              onChange={(e) => setReviewer(e.target.value)}
              autoComplete="name"
              spellCheck={false}
              maxLength={100}
              placeholder="e.g. Ana Lee…"
              disabled={disabled}
              aria-invalid={error !== null && !reviewer.trim()}
              aria-describedby={error ? "decision-error" : undefined}
              className="rounded-md border border-line-strong bg-canvas px-3 py-2 text-sm text-zinc-100 transition-colors duration-150 placeholder:text-zinc-500 focus-visible:border-cyan-400 disabled:opacity-50"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label htmlFor="comment" className="text-xs text-zinc-400">Comment (optional)</label>
            <textarea
              id="comment"
              name="comment"
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              autoComplete="off"
              maxLength={1000}
              rows={2}
              placeholder="e.g. SSH must stay private…"
              disabled={disabled}
              className="resize-none rounded-md border border-line-strong bg-canvas px-3 py-2 text-sm text-zinc-100 transition-colors duration-150 placeholder:text-zinc-500 focus-visible:border-cyan-400 disabled:opacity-50"
            />
          </div>
          <p id="decision-error" role="alert" aria-live="polite" className="text-xs text-red-300 empty:hidden">{error ?? ""}</p>
          {pending ? (
            <div className="flex flex-col gap-2 rounded-md border border-line-strong bg-raised px-3 py-3">
              <p className="text-sm text-zinc-200">
                {pending === "approve" ? "Approve" : "Deny"} as <span className="font-medium">{reviewer.trim()}</span>? This is
                recorded permanently.
              </p>
              <div className="grid grid-cols-2 gap-2">
                <button {...noFormRestore}
                  type="button"
                  onClick={() => setPending(null)}
                  disabled={busy}
                  className="rounded-md border border-line-strong px-3 py-2 text-sm text-zinc-200 transition-colors duration-150 hover:bg-white/5 active:translate-y-px disabled:opacity-40"
                >
                  Cancel
                </button>
                <button {...noFormRestore}
                  type="button"
                  onClick={() => void confirm()}
                  disabled={busy}
                  className={`rounded-md px-3 py-2 text-sm font-medium transition-colors duration-150 active:translate-y-px disabled:opacity-60 ${
                    pending === "approve" ? "bg-emerald-500 text-zinc-950 hover:bg-emerald-400" : "bg-red-500 text-white hover:bg-red-400"
                  }`}
                >
                  {busy ? "Saving…" : pending === "approve" ? "Confirm Approve" : "Confirm Deny"}
                </button>
              </div>
            </div>
          ) : (
            <div className="grid grid-cols-2 gap-2">
              <button {...noFormRestore}
                type="button"
                onClick={() => request("approve")}
                disabled={disabled}
                className="flex items-center justify-center gap-1.5 rounded-md border border-emerald-500/60 px-3 py-2 text-sm font-medium text-emerald-300 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-emerald-500/10 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40"
              >
                <CheckCircle size={16} weight="bold" aria-hidden="true" /> Approve
              </button>
              <button {...noFormRestore}
                type="button"
                onClick={() => request("deny")}
                disabled={disabled}
                className="flex items-center justify-center gap-1.5 rounded-md bg-red-500 px-3 py-2 text-sm font-medium text-white transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-red-400 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40"
              >
                <Prohibit size={16} weight="bold" aria-hidden="true" /> Deny
              </button>
            </div>
          )}
          <p className="text-[11px] leading-relaxed text-zinc-500">
            Decisions go to the append-only audit log. SimulaCrum never applies changes to any real system.
          </p>
        </div>
      )}
      <div className={blocked ? "border-t border-line" : ""}>
        <h3 className="px-4 pt-3 text-xs font-normal text-zinc-500">Audit Log</h3>
        <div aria-live="polite">
          {!blocked && (
            <p className="px-4 pb-3 pt-1 text-sm text-emerald-300/90">
              Auto-approved by SimulaCrum policy. No human review is needed or possible.
            </p>
          )}
          {decisions.length === 0 ? (
            blocked && <p className="px-4 pb-4 pt-1 text-sm text-zinc-500">No decision yet.</p>
          ) : (
            <ul className="divide-y divide-line pb-1">
              {decisions.map((d) => {
                const earlier = d.certificate_signature !== cert.signature;
                return (
                  <li key={d.id} className={`flex min-w-0 flex-col gap-0.5 px-4 py-2.5 ${earlier ? "opacity-60" : ""}`}>
                    <span className="flex flex-wrap items-center gap-x-2 text-sm">
                      <span className={`font-medium ${d.decision === "approve" ? "text-emerald-300" : "text-red-300"}`}>
                        {d.decision === "approve" ? "Approved" : "Denied"}
                      </span>
                      <span className="break-all text-zinc-300">by {d.reviewer}</span>
                      {earlier && (
                        <span className="rounded border border-line-strong px-1 font-mono text-[10px] text-zinc-400" title="Made on a previous analysis of this plan">
                          earlier version
                        </span>
                      )}
                    </span>
                    <span className="font-mono text-[11px] text-zinc-500">{formatTimestamp(d.decided_at)}</span>
                    {d.comment && <span className="break-words text-xs text-zinc-400">{d.comment}</span>}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </div>
    </Panel>
  );
}

function ResourceChanges({ cert }: { cert: Certificate }) {
  const tone: Record<string, string> = {
    create: "text-emerald-300", update: "text-amber-200", delete: "text-red-300", replace: "text-orange-300", "no-op": "text-zinc-500",
  };
  return (
    <Panel title={<>Resource Changes <span className="font-mono text-xs text-zinc-500">{cert.resource_changes.length}</span></>}>
      <ul className="divide-y divide-line">
        {cert.resource_changes.map((rc) => (
          <li key={rc.resource}>
            <details className="group">
              <summary className="flex cursor-pointer list-none items-center gap-3 px-4 py-2.5 transition-colors duration-150 hover:bg-raised/60">
                <span className={`w-16 shrink-0 font-mono text-xs ${tone[rc.action] ?? "text-zinc-400"}`}>{rc.action}</span>
                <span className="min-w-0 break-all font-mono text-sm text-zinc-200" translate="no">{rc.resource}</span>
              </summary>
              <pre className="max-h-80 overflow-auto border-t border-line bg-canvas px-4 py-3 font-mono text-xs leading-relaxed text-zinc-400" translate="no">
                {JSON.stringify(rc.after ?? rc.before, null, 2)}
              </pre>
            </details>
          </li>
        ))}
      </ul>
    </Panel>
  );
}

export default function CertificatePage() {
  const { planId } = useParams<{ planId: string }>();
  const { state, reload, mode, setState } = useCertificate(planId);

  if (state.status === "loading" || mode === "checking") {
    return (
      <div className="flex flex-col gap-4" aria-busy="true" aria-label="Loading certificate">
        <SkeletonBlock className="h-6 w-64" />
        <SkeletonBlock className="h-24" />
        <SkeletonBlock className="h-20" />
        <div className="grid gap-4 lg:grid-cols-3">
          <SkeletonBlock className="h-96 lg:col-span-2" />
          <SkeletonBlock className="h-96" />
        </div>
      </div>
    );
  }
  if (state.status === "error") {
    return (
      <div className="flex flex-col gap-4">
        <Link href="/" className="flex w-max items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} aria-hidden="true" /> Certificates
        </Link>
        <h1 className="text-xl font-semibold text-zinc-100">Certificate Unavailable</h1>
        <ErrorState
          title="Could not load this certificate"
          detail={state.error}
          hint="Check the plan id in the address bar, or go back to the certificate list."
          onRetry={() => void reload()}
        />
      </div>
    );
  }

  const detail = state.data;
  const { cert, verify } = detail;
  const signature = mode === "demo" ? "unavailable" : verify?.valid ? "verified" : "invalid";

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <Link href="/" className="flex items-center gap-1.5 text-sm text-zinc-400 transition-colors duration-150 hover:text-zinc-100">
          <ArrowLeft size={14} aria-hidden="true" /> Certificates
        </Link>
        <span className="min-w-0 break-all font-mono text-xs text-zinc-500" title={cert.plan_id} translate="no">plan {cert.plan_id}</span>
        <span className="font-mono text-xs text-zinc-500">{formatTimestamp(cert.timestamp)}</span>
        <div className="ml-auto flex items-center gap-2">
          <VerdictBadge verdict={cert.verdict} />
          <SignatureBadge state={signature} />
          <Link href={`/certificates/${cert.plan_id}/report`}
                className="flex items-center gap-1.5 rounded-md border border-line-strong px-2.5 py-1 text-xs text-zinc-200 transition-colors duration-150 hover:bg-raised">
            <FileText size={14} aria-hidden="true" /> Export Report
          </Link>
        </div>
      </div>

      <VerdictBanner cert={cert} />

      <div className="flex flex-col gap-2">
        <p className="max-w-[80ch] text-pretty text-xl leading-relaxed text-zinc-100 md:text-2xl md:leading-relaxed">{cert.risk_explanation}</p>
        <p className="font-mono text-[11px] text-zinc-500">
          explanation: {cert.generated_by === "groq" ? "Groq (from sanitized findings only)" : "template"}
        </p>
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
          <BlastRadius cert={cert} />
          <Panel title="Resource Graph (After This Change)">
            <ResourceGraph nodes={cert.blast_radius.graph.nodes} edges={cert.blast_radius.graph.edges} />
          </Panel>
          <RiskFlags cert={cert} />
          <ResourceChanges cert={cert} />
        </div>
        <div className="flex min-w-0 flex-col gap-4">
          <DecisionPanel
            detail={detail}
            demo={mode === "demo"}
            onDecided={(d) => setState({ status: "ready", data: { ...detail, decisions: [...detail.decisions, d] } })}
          />
          <Facts cert={cert} />
          <Panel title="Signature">
            <div className="flex flex-col gap-2 px-4 py-3">
              <SignatureBadge state={signature} />
              <p className="break-all font-mono text-[11px] text-zinc-500" translate="no">{signatureAlgLabel(cert.signature_alg)} {cert.signature}</p>
              <p className="text-[11px] text-zinc-500">
                {cert.signature_alg === "ed25519"
                  ? "Public-key signature: anyone can check it offline with GET /public-key and scripts/verify_certificate.py."
                  : "Shared-secret signature: only the SimulaCrum server can check it."}
              </p>
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
