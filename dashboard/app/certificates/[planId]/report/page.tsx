"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft, Printer } from "@phosphor-icons/react";
import { ErrorState, SkeletonBlock } from "@/components/states";
import { formatTimestamp, formatUsd, signatureAlgLabel } from "@/lib/format";
import { useCertificate } from "@/lib/useCertificates";
import type { Certificate, ConfigChange, Severity } from "@/lib/types";
import { SEVERITIES } from "@/lib/types";
import { noFormRestore } from "@/lib/dom";

// Print-friendly report: a light "paper" document (exception to the dark theme, because it
// is meant to be printed or saved as PDF). App chrome is hidden in print via print:hidden.

const SEV: Record<Severity, string> = {
  CRITICAL: "text-red-700", HIGH: "text-orange-700", MEDIUM: "text-amber-700", LOW: "text-zinc-600",
};

function H2({ children }: { children: React.ReactNode }) {
  return <h2 className="mt-7 border-b border-zinc-300 pb-1 text-base font-semibold text-zinc-900">{children}</h2>;
}

function change(c: ConfigChange) {
  return c.field ? `${c.service}.${c.field} = ${JSON.stringify(c.to)}` : `${c.resource}: ${c.attribute} = ${JSON.stringify(c.to)}`;
}

function Report({ cert, signature, decisions }: {
  cert: Certificate; signature: string; decisions: { decision: string; reviewer: string; decided_at: string; comment: string | null }[];
}) {
  const blocked = cert.verdict === "BLOCKED_PENDING_REVIEW";
  const flags = cert.blast_radius.risk_flags;
  const counts = SEVERITIES.map((s) => ({ s, n: flags.filter((f) => f.severity === s).length }));
  const inventory = cert.shadow_run.resources ?? [];
  const breakdown = (cert.cost_breakdown ?? []).filter((r) => r.monthly_usd !== 0 || Object.keys(r.usage_assumptions ?? {}).length);
  return (
    <article className="mx-auto max-w-[210mm] bg-white px-10 py-10 text-[13px] leading-relaxed text-zinc-800 shadow-sm print:max-w-none print:px-0 print:py-0 print:shadow-none">
      <header className="flex items-start justify-between gap-6 border-b-2 border-zinc-900 pb-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-wide text-zinc-500">SimulaCrum</p>
          <h1 className="text-2xl font-semibold text-zinc-900">Risk Certificate</h1>
          <p className="mt-1 font-mono text-[11px] text-zinc-600" translate="no">plan {cert.plan_id}</p>
        </div>
        <div className={`rounded border-2 px-3 py-2 text-right ${blocked ? "border-red-700 text-red-700" : "border-emerald-700 text-emerald-700"}`}>
          <p className="font-mono text-base font-bold">{blocked ? "BLOCKED PENDING REVIEW" : "AUTO-APPROVED"}</p>
          <p className="text-[11px]">{blocked ? "A human must approve or deny." : "Approved by policy; no review needed."}</p>
        </div>
      </header>

      <dl className="mt-4 grid grid-cols-[150px_1fr] gap-x-4 gap-y-1 text-[12px]">
        <dt className="text-zinc-500">Generated</dt><dd>{formatTimestamp(cert.timestamp)} ({cert.timestamp})</dd>
        <dt className="text-zinc-500">Signature</dt>
        <dd>
          <span className={signature === "verified" ? "font-semibold text-emerald-700" : signature === "invalid" ? "font-semibold text-red-700" : "text-zinc-600"}>
            {signature === "verified" ? "Verified" : signature === "invalid" ? "INVALID" : "Not verifiable (demo mode)"}
          </span>
          <span className="ml-2 break-all font-mono text-[10px] text-zinc-500" translate="no">{signatureAlgLabel(cert.signature_alg)} {cert.signature}</span>
        </dd>
        <dt className="text-zinc-500">Explanation by</dt><dd>{cert.generated_by === "groq" ? "Groq (sanitized findings only)" : "template"}</dd>
      </dl>

      <p className="mt-4 text-[15px] leading-relaxed text-zinc-900">{cert.risk_explanation}</p>

      <H2>Summary</H2>
      <table className="mt-2 w-full text-[12px]">
        <tbody>
          <tr><td className="w-[180px] py-0.5 text-zinc-500">Monthly cost change</td>
              <td className="font-mono">{formatUsd(cert.cost_delta.monthly_usd)}{cert.cost_delta.monthly_usd !== null && " /month"}</td></tr>
          <tr><td className="py-0.5 text-zinc-500">Shadow run (MiniStack)</td>
              <td>{cert.shadow_run.applied ? `Applied: ${cert.shadow_run.resources_created} resources in state, ${inventory.length} found by boto3` : "Not applied"}</td></tr>
          <tr><td className="py-0.5 text-zinc-500">Findings</td>
              <td>{counts.map(({ s, n }) => <span key={s} className={`mr-3 ${n ? SEV[s] : "text-zinc-400"}`}>{n} {s.toLowerCase()}</span>)}</td></tr>
          <tr><td className="py-0.5 text-zinc-500">Resource changes</td><td>{cert.resource_changes.length}</td></tr>
        </tbody>
      </table>
      {cert.cost_delta.note && <p className="mt-1 text-[11px] text-zinc-500">{cert.cost_delta.note}</p>}
      {cert.shadow_run.error && <pre className="mt-1 whitespace-pre-wrap break-words font-mono text-[10px] text-red-700">{cert.shadow_run.error}</pre>}

      <H2>Risk Flags and Fixes</H2>
      {flags.length === 0 ? <p className="mt-2 text-zinc-600">No findings.</p> : (
        <ol className="mt-2 flex flex-col gap-2.5">
          {flags.map((f, i) => (
            <li key={`${f.rule}-${f.resource}-${i}`} className="break-inside-avoid border-l-4 border-zinc-300 pl-3">
              <p className="text-[12px]">
                <span className={`font-mono font-bold ${SEV[f.severity]}`}>{f.severity}</span>
                <span className="ml-2 font-mono text-zinc-500">{f.rule}</span>
                <span className="ml-2 break-all font-mono text-zinc-900" translate="no">{f.resource}</span>
              </p>
              <p>{f.message}</p>
              {f.remediation && (
                <p className="mt-0.5 text-zinc-900">
                  <span className="font-semibold">Fix: </span>{f.remediation.summary}
                  {f.remediation.config_change.map((c, j) => (
                    <code key={j} className="ml-1 block break-all font-mono text-[11px] text-zinc-600" translate="no">{change(c)}</code>
                  ))}
                </p>
              )}
            </li>
          ))}
        </ol>
      )}

      {breakdown.length > 0 && (
        <>
          <H2>Cost Breakdown (monthly)</H2>
          <table className="mt-2 w-full text-left text-[11px]">
            <thead><tr className="border-b border-zinc-300 text-zinc-500"><th className="py-1 font-medium">Resource</th><th className="py-1 text-right font-medium">USD/month</th><th className="py-1 pl-3 font-medium">Usage assumptions</th></tr></thead>
            <tbody className="divide-y divide-zinc-200">
              {breakdown.map((r) => (
                <tr key={r.resource} className="break-inside-avoid">
                  <td className="py-1 font-mono" translate="no">{r.resource}</td>
                  <td className="py-1 text-right font-mono tabular-nums">{r.monthly_usd === null ? "n/a" : r.monthly_usd.toFixed(2)}</td>
                  <td className="py-1 pl-3 font-mono text-[10px] text-zinc-600">
                    {Object.entries(r.usage_assumptions ?? {}).map(([k, v]) => `${k}=${v}`).join(", ") || "none"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {inventory.length > 0 && (
        <>
          <H2>Shadow Environment: Resources Found in MiniStack</H2>
          <table className="mt-2 w-full text-left text-[11px]">
            <tbody className="divide-y divide-zinc-200">
              {inventory.map((r) => (
                <tr key={`${r.type}-${r.id}`} className="break-inside-avoid">
                  <td className="w-[220px] py-0.5 font-mono">{r.type}</td>
                  <td className="break-all py-0.5 font-mono text-zinc-600" translate="no">{r.name ? `${r.name} (${r.id})` : r.id}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}

      {cert.architecture && (
        <>
          <H2>Architecture</H2>
          <ul className="mt-2 flex flex-col gap-1 text-[11px]">
            {cert.architecture.services.map((s) => (
              <li key={s.name} className="break-inside-avoid">
                <span className="font-mono font-semibold text-zinc-900">{s.name}</span>
                <span className="ml-2 text-zinc-500">{s.type} · {s.analysis === "static_only" ? "static analysis only" : "shadow + static"}</span>
                <span className="block break-all font-mono text-[10px] text-zinc-600">
                  {Object.entries(s.config).filter(([k]) => k !== "name").map(([k, v]) => `${k}=${JSON.stringify(v)}`).join("  ")}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      <H2>Resource Changes</H2>
      <ul className="mt-2 columns-2 text-[11px]">
        {cert.resource_changes.map((rc) => (
          <li key={rc.resource} className="break-inside-avoid font-mono"><span className="text-zinc-500">{rc.action}</span> {rc.resource}</li>
        ))}
      </ul>

      <H2>Review</H2>
      {!blocked ? <p className="mt-2">Auto-approved by SimulaCrum policy; no human review was needed.</p>
        : decisions.length === 0 ? <p className="mt-2">Awaiting review: no decision recorded.</p> : (
        <ul className="mt-2 text-[12px]">
          {decisions.map((d, i) => (
            <li key={i}>{d.decision === "approve" ? "Approved" : "Denied"} by <b>{d.reviewer}</b> on {formatTimestamp(d.decided_at)}{d.comment ? `: ${d.comment}` : ""}</li>
          ))}
        </ul>
      )}

      {cert.generated_terraform && (
        <section className="print:break-before-page">
          <H2>Appendix: Generated Terraform</H2>
          <pre className="mt-2 whitespace-pre-wrap break-words font-mono text-[9.5px] leading-snug text-zinc-700" translate="no">{cert.generated_terraform}</pre>
        </section>
      )}

      <footer className="mt-8 border-t border-zinc-300 pt-2 text-[10px] text-zinc-500">
        Generated by SimulaCrum. Verify this certificate with GET /verify/{cert.plan_id}
        {cert.signature_alg === "ed25519" ? ", or offline with the Ed25519 public key from GET /public-key (scripts/verify_certificate.py)" : ""}.
        SimulaCrum never applies changes to a real cloud account.
      </footer>
    </article>
  );
}

export default function ReportPage() {
  const { planId } = useParams<{ planId: string }>();
  const { state, reload, mode } = useCertificate(planId);

  return (
    <div className="flex flex-col gap-4 print:gap-0">
      <div className="flex flex-wrap items-center gap-3 print:hidden">
        <Link href={`/certificates/${planId}`} className="flex items-center gap-1.5 text-sm text-zinc-400 hover:text-zinc-100">
          <ArrowLeft size={14} aria-hidden="true" /> Back to Certificate
        </Link>
        <h1 className="sr-only">Certificate Report</h1>
        <button {...noFormRestore} type="button" onClick={() => window.print()} disabled={state.status !== "ready"}
                className="ml-auto flex items-center gap-1.5 rounded-md bg-cyan-400 px-3 py-1.5 text-sm font-medium text-zinc-950 transition-colors duration-150 hover:bg-cyan-300 active:translate-y-px disabled:opacity-40">
          <Printer size={15} aria-hidden="true" /> Print / Save as PDF
        </button>
      </div>
      {state.status === "loading" || mode === "checking" ? (
        <SkeletonBlock className="mx-auto h-[600px] w-full max-w-[210mm]" />
      ) : state.status === "error" ? (
        <ErrorState title="Could not load this certificate" detail={state.error}
                    hint="Check the plan id, or go back to the certificate list." onRetry={() => void reload()} />
      ) : (
        <Report cert={state.data.cert} decisions={state.data.decisions}
                signature={mode === "demo" ? "unavailable" : state.data.verify?.valid ? "verified" : "invalid"} />
      )}
    </div>
  );
}
