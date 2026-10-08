"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle, Cube, Prohibit, SealCheck, Wrench } from "@phosphor-icons/react";
import { SEVERITY_STYLE } from "@/components/badges";
import { ErrorState, SkeletonBlock } from "@/components/states";
import { formatUsd } from "@/lib/format";
import { costByService, type ServiceCost } from "@/lib/builder";
import { PillarPanel } from "@/components/builder/PillarPanel";
import type { ArchitectureServiceInfo, Certificate, CheckResult, ConfigChange, RiskFlag, Verdict } from "@/lib/types";

export type Async<T> =
  | { status: "idle" }
  | { status: "running"; startedAt: number; forKey: string; note?: string }
  | { status: "ready"; data: T; forKey: string }
  | { status: "error"; error: string; forKey: string };

function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="font-mono tabular-nums">{Math.max(0, Math.round((now - since) / 1000))}s</span>;
}

function Section({ title, children, aside }: { title: React.ReactNode; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section className="min-w-0 border-t border-line">
      <h2 className="flex items-center gap-2 px-4 pt-3 text-xs font-medium text-zinc-400">
        {title}
        {aside && <span className="ml-auto font-normal">{aside}</span>}
      </h2>
      <div className="px-4 pb-4 pt-2">{children}</div>
    </section>
  );
}

function VerdictCard({ verdict, kind, stale }: { verdict: Verdict; kind: "check" | "certified"; stale: boolean }) {
  const blocked = verdict === "BLOCKED_PENDING_REVIEW";
  return (
    <div className={`flex items-center gap-3 rounded-md border-l-4 px-3 py-3 ${
      blocked ? "border border-red-500/50 border-l-red-500 bg-red-500/10" : "border border-emerald-500/40 border-l-emerald-500 bg-emerald-500/[0.07]"
    } ${stale ? "opacity-60" : ""}`}>
      {blocked ? <Prohibit size={22} weight="bold" className="shrink-0 text-red-300" aria-hidden="true" />
               : <CheckCircle size={22} weight="bold" className="shrink-0 text-emerald-300" aria-hidden="true" />}
      <div className="min-w-0">
        <p className={`font-mono text-sm font-semibold ${blocked ? "text-red-200" : "text-emerald-200"}`}>
          {kind === "check"
            ? (blocked ? "WOULD BE BLOCKED" : "WOULD BE AUTO-APPROVED")
            : (blocked ? "BLOCKED PENDING REVIEW" : "AUTO-APPROVED")}
        </p>
        <p className="text-[11px] text-zinc-400">
          {kind === "check" ? "Preview from the quick check (plan, OPA, graph, cost). Not signed or saved: press Certify."
                            : "Certified: full pipeline incl. MiniStack apply, signed and stored."}
          {stale && " Out of date: the architecture changed since."}
        </p>
      </div>
    </div>
  );
}

function CostPanel({ total, rows, note }: { total: number | null; rows: ServiceCost[]; note: string | null }) {
  const max = Math.max(...rows.map((r) => r.monthly_usd ?? 0), 0.01);
  return (
    <div className="flex flex-col gap-3">
      <p className="font-mono text-2xl font-semibold tabular-nums text-zinc-100">
        {formatUsd(total)}<span className="text-sm font-normal text-zinc-500"> /month</span>
      </p>
      <table className="w-full text-left text-xs">
        <thead className="sr-only"><tr><th>Service</th><th>Monthly cost</th><th>Share</th></tr></thead>
        <tbody className="divide-y divide-line">
          {rows.map((r) => (
            <tr key={r.name}>
              <td className="max-w-[120px] truncate py-1.5 pr-2 font-mono text-zinc-300" title={r.name} translate="no">{r.name}</td>
              <td className="w-[84px] py-1.5 pr-2 text-right font-mono tabular-nums text-zinc-200">
                {r.monthly_usd === null ? <span className="text-zinc-500">n/a</span> : formatUsd(r.monthly_usd).replace("+", "")}
              </td>
              <td className="w-[45%] py-1.5">
                <div className="flex items-center gap-1.5">
                  <div className="h-1.5 flex-1 overflow-hidden rounded-sm bg-raised" aria-hidden="true">
                    <div className="h-full bg-cyan-400/80" style={{ width: `${((r.monthly_usd ?? 0) / max) * 100}%` }} />
                  </div>
                  {r.usageBased && <span className="text-[10px] text-amber-300/90" title="Usage-based: set usage inputs for a real figure">min</span>}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {note && <p className="text-[11px] leading-relaxed text-zinc-500">{note}</p>}
    </div>
  );
}

function changeText(c: ConfigChange): string {
  const to = JSON.stringify(c.to);
  return c.field ? `${c.service}.${c.field} → ${to}` : `${c.resource} ${c.attribute} → ${to}`;
}

function FlagList({ flags, onApply, canApply, busy }: {
  flags: RiskFlag[]; onApply: (changes: ConfigChange[]) => void; canApply: (changes: ConfigChange[]) => boolean; busy: boolean;
}) {
  if (!flags.length) return <p className="text-sm text-zinc-400">No findings from the policy and graph checks.</p>;
  return (
    <ul className="flex flex-col gap-2">
      {flags.map((f, i) => {
        const changes = f.remediation?.config_change ?? [];
        const applicable = canApply(changes);
        return (
          <li key={`${f.rule}-${f.resource}-${i}`} className="grid grid-cols-[3px_minmax(0,1fr)] gap-x-2.5 rounded-md border border-line bg-canvas/60 px-2.5 py-2">
            <span className={`row-span-3 rounded-full ${SEVERITY_STYLE[f.severity].bar}`} aria-hidden="true" />
            <div className="flex flex-wrap items-baseline gap-x-2">
              <span className={`font-mono text-[11px] font-semibold ${SEVERITY_STYLE[f.severity].text}`}>{f.severity}</span>
              <span className="font-mono text-[11px] text-zinc-500" translate="no">{f.rule}</span>
              <span className="min-w-0 break-all font-mono text-[11px] text-zinc-300" translate="no">{f.resource}</span>
              <span className="ml-auto text-[10px] text-zinc-500">{f.pillar ?? "security"}</span>
            </div>
            <p className="break-words text-xs leading-relaxed text-zinc-400">{f.message}</p>
            {f.remediation && (
              <div className="mt-1.5 flex flex-col gap-1.5 rounded border border-line px-2 py-1.5">
                <p className="flex gap-1.5 text-xs leading-relaxed text-zinc-200">
                  <Wrench size={13} className="mt-0.5 shrink-0 text-cyan-400" aria-hidden="true" />
                  <span>{f.remediation.summary}</span>
                </p>
                {changes.map((c, j) => (
                  <code key={j} className="block break-all font-mono text-[11px] text-cyan-200/90" translate="no">{changeText(c)}</code>
                ))}
                {applicable && (
                  <button type="button" disabled={busy} onClick={() => onApply(changes)}
                          className="w-max rounded-md border border-cyan-400/60 px-2.5 py-1 text-xs font-medium text-cyan-200 transition-colors duration-150 hover:bg-cyan-400/10 active:translate-y-px disabled:opacity-40">
                    Apply Fix
                  </button>
                )}
              </div>
            )}
          </li>
        );
      })}
    </ul>
  );
}

function ShadowPanel({ full, stale }: { full: Async<Certificate>; stale: boolean }) {
  if (full.status === "running") {
    return (
      <div className="flex flex-col gap-2" aria-busy="true">
        <p className="text-xs text-zinc-400">Applying on MiniStack… <Elapsed since={full.startedAt} /> (usually 40 to 150 s)</p>
        <SkeletonBlock className="h-16" />
      </div>
    );
  }
  if (full.status !== "ready") {
    return (
      <p className="text-xs leading-relaxed text-zinc-500">
        {full.status === "error" ? "The last full analysis failed (see above). " : ""}
        Nothing applied yet. Press <span className="text-zinc-300">Certify</span> to apply this architecture on a fresh
        MiniStack and list what really gets created.
      </p>
    );
  }
  const run = full.data.shadow_run;
  const groups = new Map<string, string[]>();
  for (const r of run.resources ?? []) groups.set(r.type, [...(groups.get(r.type) ?? []), r.name ? `${r.name} (${r.id})` : r.id]);
  return (
    <div className={`flex flex-col gap-2 ${stale ? "opacity-60" : ""}`}>
      <p className={`text-xs ${run.applied ? "text-emerald-300" : "text-red-300"}`}>
        {run.applied ? `Applied: ${run.resources_created} resources in Terraform state, ${run.resources?.length ?? 0} found by boto3`
                     : "Apply failed or skipped"}
        {stale && <span className="text-zinc-500"> · out of date</span>}
      </p>
      {run.error && <pre className="max-h-40 overflow-auto whitespace-pre-wrap break-words font-mono text-[11px] text-red-200/80">{run.error}</pre>}
      {run.inventory_error && <p className="text-[11px] text-amber-300">Inventory incomplete: {run.inventory_error}</p>}
      <ul className="divide-y divide-line">
        {[...groups.entries()].map(([type, ids]) => (
          <li key={type} className="flex flex-col gap-0.5 py-1.5">
            <span className="flex items-center gap-1.5 font-mono text-xs text-zinc-300">
              <Cube size={12} className="text-zinc-500" aria-hidden="true" />{type}
              <span className="text-zinc-500">×{ids.length}</span>
            </span>
            {ids.map((id) => <span key={id} className="break-all pl-4 font-mono text-[10px] text-zinc-500" translate="no">{id}</span>)}
          </li>
        ))}
      </ul>
      <p className="text-[11px] text-zinc-500">MiniStack was reset after the run; these resources no longer exist.</p>
    </div>
  );
}

export function ResultsPanel({
  hasServices, invalid, check, full, terraform, previewServices, owners,
  checkFresh, fullFresh, onAnalyze, onApply, canApply,
}: {
  hasServices: boolean;
  invalid: boolean;
  check: Async<CheckResult>;
  full: Async<Certificate>;
  terraform: string | null;
  previewServices: ArchitectureServiceInfo[];
  owners: Map<string, string>;
  checkFresh: boolean;
  fullFresh: boolean;
  onAnalyze: () => void;
  onApply: (changes: ConfigChange[]) => void;
  canApply: (changes: ConfigChange[]) => boolean;
}) {
  const fullReady = full.status === "ready" ? full.data : null;
  const checkReady = check.status === "ready" ? check.data : null;
  // Prefer the certified result when it matches the current architecture.
  const useFull = fullReady && fullFresh;
  const flags = useFull ? fullReady.blast_radius.risk_flags : checkReady?.risk_flags ?? [];
  const costRows = useFull ? fullReady.cost_breakdown ?? [] : checkReady?.cost_breakdown ?? [];
  const costTotal = useFull ? fullReady.cost_delta.monthly_usd : checkReady?.cost_delta.monthly_usd ?? null;
  const costNote = useFull ? fullReady.cost_delta.note : checkReady?.cost_delta.note ?? null;
  const pillars = (useFull ? fullReady.pillars : undefined) ?? checkReady?.pillars ?? null;
  const perService = costByService(costRows, owners, previewServices);
  const showResults = Boolean(useFull || checkReady);

  return (
    <aside className="flex min-w-0 flex-col rounded-md border border-line bg-surface" aria-label="Analysis">
      <div className="flex items-center gap-2 px-4 py-3">
        <h2 className="text-sm font-medium text-zinc-200">Analysis</h2>
        <span className="ml-auto text-[11px] text-zinc-500" aria-live="polite">
          {check.status === "running" && <>Checking… <Elapsed since={check.startedAt} /></>}
          {check.status === "ready" && checkFresh && `Checked in ${check.data.duration_s}s`}
          {check.status === "ready" && !checkFresh && !invalid && "Changes pending…"}
        </span>
        <button type="button" onClick={onAnalyze} disabled={!hasServices || invalid || full.status === "running"}
                className="flex items-center gap-1.5 rounded-md bg-cyan-400 px-3 py-1.5 text-xs font-medium text-zinc-950 transition-colors duration-150 hover:bg-cyan-300 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40">
          <SealCheck size={14} weight="bold" aria-hidden="true" /> {full.status === "running" ? "Certifying…" : "Certify"}
        </button>
      </div>
      <p className="-mt-1 px-4 pb-3 text-[11px] leading-relaxed text-zinc-500">
        {full.status === "running" ? (
          <>Running the full check on MiniStack… <Elapsed since={full.startedAt} /> (1 to 2 min, longer for big designs).
          {full.note ? ` ${full.note}` : ""} It runs on the server: you can leave this page, and the result will appear on
          the Certificates page.</>
        ) : (
          <>The verdict below is a quick preview. <span className="text-zinc-300">Certify</span> runs the full check (policy, a real
          MiniStack apply, cost), signs it and saves it to the Certificates page.</>
        )}
      </p>

      {!hasServices ? (
        <p className="border-t border-line px-4 py-8 text-sm text-zinc-500">Add a service to see the verdict, cost and risks.</p>
      ) : (
        <>
          {invalid && <p role="alert" className="border-t border-line px-4 py-3 text-xs text-red-300">Fix the highlighted fields; nothing is analysed until the architecture is valid.</p>}
          {full.status === "error" && (
            <div className="border-t border-line p-3">
              <ErrorState title="Full analysis failed" detail={full.error}
                          hint="Check that MiniStack and the API are running, then press Certify again." onRetry={onAnalyze} />
            </div>
          )}
          {check.status === "error" && (
            <div className="border-t border-line p-3">
              <ErrorState title="Static check failed" detail={check.error} hint="Edit the architecture to retry the check." />
            </div>
          )}
          {!showResults && check.status === "running" && (
            <div className="flex flex-col gap-2 border-t border-line p-4" aria-busy="true">
              <SkeletonBlock className="h-14" /><SkeletonBlock className="h-24" /><SkeletonBlock className="h-32" />
            </div>
          )}
          {showResults && (
            <>
              <div className="border-t border-line p-4">
                <VerdictCard verdict={useFull ? fullReady.verdict : checkReady!.verdict_preview}
                             kind={useFull ? "certified" : "check"} stale={!useFull && !checkFresh} />
                {useFull && (
                  <Link href={`/certificates/${fullReady.plan_id}`}
                        className="mt-2 flex w-max items-center gap-1 text-xs text-cyan-300 hover:text-cyan-200">
                    <SealCheck size={13} aria-hidden="true" /> Saved to Certificates · Open certificate <ArrowRight size={12} aria-hidden="true" />
                  </Link>
                )}
              </div>
              {pillars && (
                <Section title="Pillar Scores"
                         aside={!useFull && !checkFresh ? <span className="text-zinc-500">{check.status === "running" ? "updating…" : "out of date"}</span> : null}>
                  <PillarPanel pillars={pillars} stale={!useFull && !checkFresh} />
                </Section>
              )}
              <Section title="Monthly Cost">
                <CostPanel total={costTotal} rows={perService} note={costNote} />
              </Section>
              <Section title={<>Risk Flags <span className="font-mono text-zinc-500">{flags.length}</span></>}>
                <FlagList flags={flags} onApply={onApply} canApply={canApply} busy={full.status === "running"} />
              </Section>
            </>
          )}
          <Section title="Shadow Environment (MiniStack)">
            <ShadowPanel full={full} stale={!fullFresh} />
          </Section>
          <Section title="Generated Terraform">
            {terraform ? (
              <details>
                <summary className="cursor-pointer text-xs text-zinc-300 hover:text-zinc-100">
                  main.tf · {terraform.split("\n").length} lines
                </summary>
                <pre className="mt-2 max-h-96 overflow-auto rounded border border-line bg-canvas p-2 font-mono text-[11px] leading-relaxed text-zinc-300" translate="no">
                  {terraform}
                </pre>
              </details>
            ) : <p className="text-xs text-zinc-500">Appears when the architecture is valid.</p>}
          </Section>
        </>
      )}
    </aside>
  );
}
