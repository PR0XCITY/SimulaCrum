"use client";

import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle, Compass, CurrencyDollar, Prohibit, Scales, Wrench } from "@phosphor-icons/react";
import { ErrorState, SkeletonBlock } from "@/components/states";
import { formatUsd } from "@/lib/format";
import { PILLARS, type AdvisorImpact, type AdvisorRecommendation, type AdvisorResult, type ConfigChange, type Pillar, type Verdict } from "@/lib/types";
import type { Async } from "@/components/builder/ResultsPanel";

const PILLAR_LABEL: Record<Pillar, string> = {
  security: "Security", reliability: "Reliability", cost: "Cost", performance: "Performance",
};

function Elapsed({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="font-mono tabular-nums">{Math.max(0, Math.round((now - since) / 1000))}s</span>;
}

// formatUsd signs every value (it is made for deltas): fine for a change, not for a total.
const money = (delta: number) => `${formatUsd(delta)}/mo`;
const total = (usd: number) => formatUsd(usd).replace(/^\+/, "");

function VerdictWord({ verdict }: { verdict: Verdict }) {
  const blocked = verdict === "BLOCKED_PENDING_REVIEW";
  const Glyph = blocked ? Prohibit : CheckCircle;
  return (
    <span className={`inline-flex items-center gap-1 font-mono text-xs font-semibold ${blocked ? "text-red-300" : "text-emerald-300"}`}>
      <Glyph size={13} weight="bold" aria-hidden="true" />
      {blocked ? "BLOCKED" : "AUTO-APPROVED"}
    </span>
  );
}

function Chip({ tone, children }: { tone: "good" | "warn" | "neutral"; children: React.ReactNode }) {
  const style = tone === "good" ? "border-emerald-500/40 text-emerald-200"
    : tone === "warn" ? "border-amber-500/40 text-amber-200" : "border-line-strong text-zinc-400";
  return <span className={`rounded border px-1.5 py-0.5 font-mono text-[10px] tabular-nums ${style}`}>{children}</span>;
}

function ImpactChips({ impact }: { impact: AdvisorImpact }) {
  return (
    <div className="flex flex-wrap gap-1.5">
      {impact.unblocks && <Chip tone="good">unblocks the design</Chip>}
      {impact.blocking_removed > 0 && (
        <Chip tone="good">-{impact.blocking_removed} blocking finding{impact.blocking_removed === 1 ? "" : "s"}</Chip>
      )}
      {PILLARS.filter((p) => impact.points_removed[p] > 0).map((p) => (
        <Chip key={p} tone="good">{PILLAR_LABEL[p]} +{impact.points_removed[p]} pts</Chip>
      ))}
      {impact.cost_usd !== null && Math.abs(impact.cost_usd) >= 0.01 && (
        <Chip tone={impact.cost_usd < 0 ? "good" : "warn"}>{money(impact.cost_usd)}</Chip>
      )}
      {impact.tradeoffs.filter((t) => !t.startsWith("+$")).map((t) => <Chip key={t} tone="warn">{t}</Chip>)}
    </div>
  );
}

function Recommendation({ rec, onApply, canApply }: {
  rec: AdvisorRecommendation; onApply: (changes: ConfigChange[]) => void; canApply: (changes: ConfigChange[]) => boolean;
}) {
  const tradeoff = rec.impact.tradeoffs.length > 0;
  const Glyph = tradeoff ? Scales : rec.kind === "save" ? CurrencyDollar : Wrench;
  return (
    <li className="flex gap-3 py-3">
      <Glyph size={16} className={`mt-0.5 shrink-0 ${tradeoff ? "text-amber-300" : rec.kind === "save" ? "text-emerald-300" : "text-cyan-400"}`}
             aria-hidden="true" />
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <p className="text-sm text-zinc-200">{rec.summary}</p>
        <p className="break-words font-mono text-[11px] text-zinc-500" translate="no">
          {rec.title}{rec.rules.length > 0 && <> · fixes {rec.rules.join(", ")}</>}
        </p>
        <ImpactChips impact={rec.impact} />
      </div>
      <button type="button" onClick={() => onApply(rec.changes)} disabled={!canApply(rec.changes)}
              className="h-fit shrink-0 rounded-md border border-cyan-500/40 px-2.5 py-1 text-xs text-cyan-200 transition-colors duration-150 hover:bg-cyan-500/10 disabled:opacity-40">
        Apply
      </button>
    </li>
  );
}

function Group({ title, hint, recs, onApply, canApply }: {
  title: string; hint: string; recs: AdvisorRecommendation[];
  onApply: (changes: ConfigChange[]) => void; canApply: (changes: ConfigChange[]) => boolean;
}) {
  if (!recs.length) return null;
  return (
    <div className="flex flex-col">
      <h3 className="flex items-baseline gap-2 text-xs font-medium text-zinc-300">
        {title} <span className="font-mono text-zinc-500">{recs.length}</span>
        <span className="ml-auto text-[11px] font-normal text-zinc-500">{hint}</span>
      </h3>
      <ul className="divide-y divide-line">
        {recs.map((r) => <Recommendation key={r.id} rec={r} onApply={onApply} canApply={canApply} />)}
      </ul>
    </div>
  );
}

function Combined({ result, onApply, canApply }: {
  result: AdvisorResult; onApply: (changes: ConfigChange[]) => void; canApply: (changes: ConfigChange[]) => boolean;
}) {
  const combined = result.combined;
  if (!combined) return null;
  const { impact } = combined;
  const before = result.baseline;
  const n = combined.ids.length;
  return (
    <div className="flex flex-col gap-3 rounded-md border border-cyan-500/30 bg-cyan-500/[0.04] p-3">
      <div className="flex flex-wrap items-center gap-2">
        <p className="text-sm font-medium text-zinc-100">
          Apply the {n} recommended change{n === 1 ? "" : "s"} without trade-offs
        </p>
        <button type="button" onClick={() => onApply(combined.changes)} disabled={!canApply(combined.changes)}
                className="ml-auto rounded-md bg-cyan-500 px-3 py-1.5 text-xs font-medium text-zinc-950 transition-colors duration-150 hover:bg-cyan-400 disabled:opacity-40">
          Apply All {n}
        </button>
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <VerdictWord verdict={before.verdict} />
        <ArrowRight size={12} className="text-zinc-500" aria-hidden="true" />
        <VerdictWord verdict={impact.verdict_after} />
      </div>
      <dl className="grid grid-cols-2 gap-2 sm:grid-cols-5">
        {PILLARS.map((p) => (
          <div key={p} className="rounded-md border border-line bg-canvas/60 px-2 py-1.5">
            <dt className="text-[10px] text-zinc-500">{PILLAR_LABEL[p]}</dt>
            <dd className="font-mono text-sm tabular-nums text-zinc-200">
              {before.pillars[p]}
              <span className="text-zinc-500"> → </span>
              <span className={impact.pillars_after[p] > before.pillars[p] ? "text-emerald-300" : ""}>{impact.pillars_after[p]}</span>
            </dd>
          </div>
        ))}
        <div className="rounded-md border border-line bg-canvas/60 px-2 py-1.5">
          <dt className="text-[10px] text-zinc-500">Monthly cost</dt>
          <dd className="font-mono text-sm tabular-nums text-zinc-200">
            {impact.monthly_after_usd === null ? "unknown" : total(impact.monthly_after_usd)}
            {impact.cost_usd !== null && Math.abs(impact.cost_usd) >= 0.01 && (
              <span className={`block text-[10px] ${impact.cost_usd < 0 ? "text-emerald-300" : "text-amber-300"}`}>
                {money(impact.cost_usd)}
              </span>
            )}
          </dd>
        </div>
      </dl>
    </div>
  );
}

export function AdvisorPanel({ state, stale, disabled, onAsk, onApply, canApply }: {
  state: Async<AdvisorResult>;
  stale: boolean;
  disabled: boolean;
  onAsk: () => void;
  onApply: (changes: ConfigChange[]) => void;
  canApply: (changes: ConfigChange[]) => boolean;
}) {
  const running = state.status === "running";
  const result = state.status === "ready" ? state.data : null;
  const recs = result?.recommendations ?? [];
  const clean = recs.filter((r) => !r.impact.tradeoffs.length);
  return (
    <section className="min-w-0 rounded-md border border-line bg-surface" aria-label="Trusted Advisor">
      <div className="flex flex-wrap items-center gap-3 border-b border-line px-4 py-2.5">
        <Compass size={16} className="text-cyan-400" aria-hidden="true" />
        <h2 className="text-sm font-medium text-zinc-300">Trusted Advisor</h2>
        <button type="button" onClick={onAsk} disabled={disabled || running}
                className="ml-auto rounded-md border border-cyan-500/50 px-3 py-1.5 text-xs font-medium text-cyan-200 transition-colors duration-150 hover:bg-cyan-500/10 disabled:opacity-40">
          {running ? "Measuring..." : result ? "Ask Again" : "Ask the Advisor"}
        </button>
      </div>
      <div className="flex flex-col gap-4 px-4 py-3">
        {state.status === "idle" && (
          <p className="text-xs leading-relaxed text-zinc-400">
            When your design is ready, ask the advisor which changes make it safer, more reliable or cheaper. It tries
            each fix and each cheaper size for real: Terraform plans it, the same rules score it and Infracost prices it,
            so every number shown is measured. Takes about 1 to 3 minutes.
          </p>
        )}
        {running && (
          <div className="flex flex-col gap-2" aria-live="polite">
            <p className="text-xs text-zinc-400">
              Planning and pricing every candidate change... <Elapsed since={state.startedAt} />
              {state.note && <span className="block text-zinc-500">{state.note}</span>}
            </p>
            {[0, 1, 2].map((i) => <SkeletonBlock key={i} className="h-14" />)}
          </div>
        )}
        {state.status === "error" && (
          <ErrorState title="The advisor could not finish" detail={state.error} hint="Check the API, then ask again." onRetry={onAsk} />
        )}
        {result && (
          <div className={`flex flex-col gap-4 transition-opacity duration-150 ${stale ? "opacity-60" : ""}`}>
            {stale && (
              <p className="text-[11px] text-amber-300">
                The design changed since this advice: the numbers below were measured on the earlier version. Ask again to refresh.
              </p>
            )}
            {recs.length === 0 ? (
              <p className="flex items-center gap-2 text-sm text-emerald-200">
                <CheckCircle size={16} weight="bold" aria-hidden="true" />
                Nothing to improve: no change the advisor tried made this design safer, more reliable or cheaper.
              </p>
            ) : (
              <>
                {clean.length > 1 && <Combined result={result} onApply={onApply} canApply={canApply} />}
                <Group title="Fixes" hint="removes findings, no trade-off" onApply={onApply} canApply={canApply}
                       recs={recs.filter((r) => r.kind === "fix" && !r.impact.tradeoffs.length)} />
                <Group title="Savings" hint="cheaper, same scores" onApply={onApply} canApply={canApply}
                       recs={recs.filter((r) => r.kind === "save" && !r.impact.tradeoffs.length)} />
                <Group title="Trade-offs" hint="better in one way, worse in another" onApply={onApply} canApply={canApply}
                       recs={recs.filter((r) => r.impact.tradeoffs.length > 0)} />
              </>
            )}
            <p className="text-[11px] leading-relaxed text-zinc-500">
              Measured {result.candidates_measured} candidate change{result.candidates_measured === 1 ? "" : "s"} in{" "}
              <span className="font-mono tabular-nums">{Math.round(result.duration_s)}s</span>; changes that measured
              no improvement are not shown. Points are the pillar penalty points a change removes (scores stop at 0).
              {result.candidates_failed > 0 && ` ${result.candidates_failed} could not be planned.`}
              {result.cost_note && ` ${result.cost_note}`}
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
