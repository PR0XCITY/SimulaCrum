"use client";

import Link from "next/link";
import { ArrowRight, Blueprint, FileCode, SealCheck, UserCheck } from "@phosphor-icons/react";
import type { Icon } from "@phosphor-icons/react";
import { SeverityBadge, VerdictBadge } from "@/components/badges";
import { EmptyState, ErrorState, SkeletonRows } from "@/components/states";
import { formatTimestamp, formatUsd, shortHash, topSeverity } from "@/lib/format";
import { useCertificateList } from "@/lib/useCertificates";
import { PILLARS, type CertificateSummary, type Pillar } from "@/lib/types";

const PILLAR_SHORT: Record<Pillar, string> = { security: "Sec", reliability: "Rel", cost: "Cost", performance: "Perf" };

function Stat({ label, value, tone }: { label: string; value: number; tone: string }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-xs text-zinc-500">{label}</span>
      <span className={`font-mono text-2xl font-semibold tabular-nums ${tone}`}>{value}</span>
    </div>
  );
}

function Step({ n, icon: Glyph, title, body }: { n: number; icon: Icon; title: string; body: string }) {
  return (
    <li className="flex min-w-0 gap-3 px-4 py-3">
      <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-line bg-raised text-cyan-300">
        <Glyph size={15} aria-hidden="true" />
      </span>
      <div className="min-w-0">
        <p className="text-sm text-zinc-200"><span className="mr-1.5 font-mono text-xs text-zinc-500">{n}</span>{title}</p>
        <p className="text-xs leading-relaxed text-zinc-500">{body}</p>
      </div>
    </li>
  );
}

function HowItWorks() {
  return (
    <ol aria-label="How certificates are made" className="grid divide-y divide-line rounded-md border border-line bg-surface md:grid-cols-3 md:divide-x md:divide-y-0">
      <Step n={1} icon={Blueprint} title="Design in the Builder"
            body="Pick services and settings. A quick check runs as you edit; it is a preview and is not saved." />
      <Step n={2} icon={SealCheck} title="Certify it"
            body="Runs the full check: policy rules, a real apply on MiniStack, cost and a signature. The result lands here." />
      <Step n={3} icon={UserCheck} title="Review if blocked"
            body="Security risks or an over-budget cost block the change until a reviewer approves or denies it." />
    </ol>
  );
}

function scoreTone(score: number) {
  return score >= 90 ? "text-emerald-300" : score >= 60 ? "text-amber-300" : "text-orange-300";
}

function PillarScores({ scores }: { scores: CertificateSummary["pillar_scores"] }) {
  if (!scores) return <span className="font-mono text-xs text-zinc-600">n/a</span>;
  return (
    <div className="grid grid-cols-4 gap-2" aria-label="Pillar scores">
      {PILLARS.map((p) => (
        <div key={p} className="flex flex-col items-center leading-tight" title={`${p} ${scores[p]}/100`}>
          <span className={`font-mono text-xs font-semibold tabular-nums ${scoreTone(scores[p])}`}>{scores[p]}</span>
          <span className="text-[10px] text-zinc-600">{PILLAR_SHORT[p]}</span>
        </div>
      ))}
    </div>
  );
}

function Source({ c }: { c: CertificateSummary }) {
  const href = `/certificates/${c.plan_id}`;
  const services = c.source?.services ?? [];
  if (c.source?.kind === "builder" && services.length) {
    const names = services.slice(0, 3).map((s) => s.name).join(", ") + (services.length > 3 ? ` +${services.length - 3}` : "");
    return (
      <>
        <Link href={href} translate="no" className="flex items-center gap-1.5 font-mono text-sm text-zinc-200 underline-offset-4 hover:text-cyan-300 hover:underline">
          <Blueprint size={14} className="shrink-0 text-cyan-400/80" aria-hidden="true" />{names}
        </Link>
        <span className="text-xs text-zinc-500">
          Builder design · {services.length} service{services.length === 1 ? "" : "s"} · <span translate="no">{shortHash(c.plan_id, 8)}</span>
        </span>
      </>
    );
  }
  return (
    <>
      <Link href={href} translate="no" className="flex items-center gap-1.5 font-mono text-sm text-zinc-200 underline-offset-4 hover:text-cyan-300 hover:underline">
        <FileCode size={14} className="shrink-0 text-zinc-500" aria-hidden="true" />{shortHash(c.plan_id)}
      </Link>
      <span className="text-xs text-zinc-500">Terraform plan (CLI, API or demo)</span>
    </>
  );
}

function Row({ c }: { c: CertificateSummary }) {
  const blocked = c.verdict === "BLOCKED_PENDING_REVIEW";
  const href = `/certificates/${c.plan_id}`;
  const top = topSeverity(c.risk_flag_counts);
  const flagCount = Object.values(c.risk_flag_counts).reduce((a, b) => a + b, 0);
  return (
    <tr
      className={`border-l-2 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-raised/70 ${
        blocked ? "border-l-red-500 bg-red-500/[0.04]" : "border-l-emerald-500/70"
      }`}
    >
      <td className="px-4 py-3.5">
        <VerdictBadge verdict={c.verdict} />
      </td>
      <td className="px-4 py-3.5">
        <div className="flex min-w-0 flex-col gap-0.5">
          <Source c={c} />
          <span className="text-xs text-zinc-500">
            {c.resource_change_count} change{c.resource_change_count === 1 ? "" : "s"}
            {!blocked ? (
              // Auto-approved certificates are approved by policy; no human review is involved.
              <span className="text-emerald-400/90"> · auto-approved by policy</span>
            ) : c.latest_decision ? (
              <span className={c.latest_decision.decision === "approve" ? "text-emerald-400/90" : "text-red-400/90"}>
                {" "}· {c.latest_decision.decision === "approve" ? "approved" : "denied"} by {c.latest_decision.reviewer}
              </span>
            ) : (
              <span className="text-amber-300/90"> · awaiting review</span>
            )}
          </span>
        </div>
      </td>
      <td className="px-4 py-3.5">
        <PillarScores scores={c.pillar_scores} />
      </td>
      <td className="px-4 py-3.5">
        <div className="flex items-center gap-2">
          <SeverityBadge severity={top} />
          {flagCount > 0 && (
            <span className="font-mono text-xs text-zinc-500">
              {flagCount} flag{flagCount === 1 ? "" : "s"}
              {c.blocking_count ? <span className="text-red-300/90"> · {c.blocking_count} blocking</span> : null}
            </span>
          )}
        </div>
      </td>
      <td className={`px-4 py-3.5 text-right font-mono text-sm tabular-nums ${c.monthly_usd === null ? "text-zinc-500" : "text-zinc-200"}`}>
        {formatUsd(c.monthly_usd)}
        {c.monthly_usd !== null && <span className="text-zinc-500">/mo</span>}
      </td>
      <td className="px-4 py-3.5 text-right font-mono text-xs text-zinc-400 tabular-nums">{formatTimestamp(c.timestamp)}</td>
      <td className="px-2 py-2">
        <Link
          href={href}
          aria-label={`Open certificate ${shortHash(c.plan_id)}`}
          className="flex h-8 w-8 items-center justify-center rounded-md text-zinc-500 transition-colors duration-150 ease-[var(--ease-snap)] hover:bg-raised hover:text-cyan-300"
        >
          <ArrowRight size={16} aria-hidden="true" />
        </Link>
      </td>
    </tr>
  );
}

const CERTIFY_LINK = "inline-flex items-center gap-2 rounded-md bg-cyan-400 px-3 py-2 text-sm font-medium text-zinc-950 transition-transform duration-150 ease-[var(--ease-snap)] hover:bg-cyan-300 active:translate-y-px";

export default function Home() {
  const { state, reload, mode } = useCertificateList();
  const rows = state.status === "ready" ? state.data : [];
  const blocked = rows.filter((r) => r.verdict === "BLOCKED_PENDING_REVIEW").length;

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-wrap items-end justify-between gap-6">
        <div className="flex max-w-2xl flex-col gap-1">
          <h1 className="text-balance text-2xl font-semibold tracking-tight text-zinc-50">Risk Certificates</h1>
          <p className="text-sm text-zinc-400">
            Every design or plan SimulaCrum has certified, newest first. A certificate is the signed record of the full
            check: what would change, what is risky, what it costs, and whether it is allowed through.
          </p>
        </div>
        <div className="flex items-end gap-8">
          {state.status === "ready" && rows.length > 0 && (
            <div className="flex gap-8">
              <Stat label="Blocked" value={blocked} tone={blocked ? "text-red-400" : "text-zinc-300"} />
              <Stat label="Auto-approved" value={rows.length - blocked} tone="text-emerald-400" />
              <Stat label="Total" value={rows.length} tone="text-zinc-200" />
            </div>
          )}
          <Link href="/builder" className={CERTIFY_LINK}>
            <SealCheck size={15} weight="bold" aria-hidden="true" /> Certify a Design
          </Link>
        </div>
      </div>

      <HowItWorks />

      <div className="overflow-hidden rounded-md border border-line bg-surface">
        {state.status === "loading" || mode === "checking" ? (
          <SkeletonRows rows={4} cols={6} />
        ) : state.status === "error" ? (
          <div className="p-4">
            <ErrorState
              title="Could not load certificates"
              detail={state.error}
              hint="Check that the SimulaCrum API is running (python -m app.server), then retry."
              onRetry={() => void reload()}
            />
          </div>
        ) : rows.length === 0 ? (
          <EmptyState
            title="No Certificates Yet"
            body="Build a design in the Builder (or load an example) and press Certify. The signed result appears here. Plans checked with the SimulaCrum CLI (ghostops analyze) show up here too."
            action={
              <Link href="/builder" className={`mt-1 ${CERTIFY_LINK}`}>
                Open Builder <ArrowRight size={14} weight="bold" aria-hidden="true" />
              </Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[900px] text-left">
              <thead>
                <tr className="border-b border-line text-xs text-zinc-500">
                  <th className="px-4 py-2.5 font-medium">Verdict</th>
                  <th className="px-4 py-2.5 font-medium">Design</th>
                  <th className="px-4 py-2.5 font-medium">Pillar scores</th>
                  <th className="px-4 py-2.5 font-medium">Top severity</th>
                  <th className="px-4 py-2.5 text-right font-medium">Cost delta</th>
                  <th className="px-4 py-2.5 text-right font-medium">Certified</th>
                  <th className="w-8" />
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map((c) => (
                  <Row key={c.plan_id} c={c} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
