"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import {
  ArrowRight, CurrencyDollar, CurrencyDollarSimple, Equals, Lifebuoy, Lightning, PencilSimple, ShieldCheck, Trash,
} from "@phosphor-icons/react";
import type { Icon } from "@phosphor-icons/react";
import { useMode } from "@/components/ModeProvider";
import { SEVERITY_STYLE, VerdictBadge } from "@/components/badges";
import { EmptyState, ErrorState, SkeletonBlock } from "@/components/states";
import { api } from "@/lib/api";
import { SLOTS, type Comparison, type SavedDesign, type Slot } from "@/lib/compare";
import { formatTimestamp, formatUsd } from "@/lib/format";
import { PILLARS, SEVERITIES, type Pillar } from "@/lib/types";

const PILLAR_META: Record<Pillar, { label: string; icon: Icon }> = {
  security: { label: "Security", icon: ShieldCheck },
  reliability: { label: "Reliability", icon: Lifebuoy },
  cost: { label: "Cost", icon: CurrencyDollar },
  performance: { label: "Performance", icon: Lightning },
};

const other = (slot: Slot): Slot => (slot === "A" ? "B" : "A");
const usd = (v: number | null) => formatUsd(v).replace("+", "");

function scoreTone(score: number) {
  if (score >= 90) return { text: "text-emerald-300", bar: "bg-emerald-500" };
  if (score >= 60) return { text: "text-amber-300", bar: "bg-amber-400" };
  return { text: "text-orange-300", bar: "bg-orange-500" };
}

function show(value: unknown): string {
  if (value === null || value === undefined) return "default";
  if (Array.isArray(value)) return value.join(", ");
  return String(value);
}

function WinnerChip({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1 rounded border border-emerald-500/50 bg-emerald-500/15 px-1.5 py-0.5 text-[11px] font-medium text-emerald-200">
      {children}
    </span>
  );
}

function Highlight({ icon: Glyph, title, slot, reason }: { icon: Icon; title: string; slot: Slot | "tie" | null; reason: string }) {
  const decided = slot === "A" || slot === "B";
  return (
    <div className={`flex min-w-0 flex-1 items-center gap-3 rounded-md border px-4 py-3 ${
      decided ? "border-emerald-500/40 border-l-4 border-l-emerald-500 bg-emerald-500/[0.07]" : "border-line bg-surface"
    }`}>
      {decided ? <Glyph size={22} weight="bold" className="shrink-0 text-emerald-300" aria-hidden="true" />
               : <Equals size={22} className="shrink-0 text-zinc-500" aria-hidden="true" />}
      <div className="min-w-0">
        <p className="text-xs text-zinc-400">{title}</p>
        <p className={`font-mono text-base font-semibold ${decided ? "text-emerald-200" : "text-zinc-300"}`}>
          {decided ? `Design ${slot}` : slot === "tie" ? "Tie" : "Unknown"}
        </p>
        <p className="text-xs text-zinc-400">{reason}</p>
      </div>
    </div>
  );
}

function EmptySlot({ slot }: { slot: Slot }) {
  return (
    <section aria-label={`Design ${slot}`} className="flex min-h-[260px] flex-col items-center justify-center gap-2 rounded-md border border-dashed border-line-strong p-6 text-center">
      <p className="font-mono text-lg font-semibold text-zinc-300">Design {slot}</p>
      <p className="max-w-xs text-sm text-zinc-500">Empty. Build a design, then press <span className="text-zinc-300">Save as {slot}</span>.</p>
      <Link href="/builder" className="mt-1 inline-flex items-center gap-1 text-sm text-cyan-300 hover:text-cyan-200">
        Open Builder <ArrowRight size={13} aria-hidden="true" />
      </Link>
    </section>
  );
}

function DesignCard({ design, rival, cheaper, fewerRisks, onRemove, removing }: {
  design: SavedDesign; rival: SavedDesign | null; cheaper: boolean; fewerRisks: boolean;
  onRemove: () => void; removing: boolean;
}) {
  const s = design.snapshot;
  const r = rival?.snapshot ?? null;
  const counts = SEVERITIES.map((sev) => ({ sev, n: s.risk_flags.filter((f) => f.severity === sev).length }));
  const costDiff = r && s.monthly_usd !== null && r.monthly_usd !== null ? s.monthly_usd - r.monthly_usd : null;
  return (
    <section aria-label={`Design ${design.slot}`}
             className={`flex min-w-0 flex-col rounded-md border bg-surface ${cheaper || fewerRisks ? "border-emerald-500/40" : "border-line"}`}>
      <header className="flex flex-wrap items-center gap-2 border-b border-line px-4 py-3">
        <h2 className="font-mono text-lg font-semibold text-zinc-100">Design {design.slot}</h2>
        {cheaper && <WinnerChip><CurrencyDollarSimple size={12} weight="bold" aria-hidden="true" /> Cheaper</WinnerChip>}
        {fewerRisks && <WinnerChip><ShieldCheck size={12} weight="bold" aria-hidden="true" /> Fewer risks</WinnerChip>}
        <div className="ml-auto flex items-center gap-1">
          <Link href={`/builder?load=${design.slot}`} aria-label={`Open design ${design.slot} in the Builder`}
                className="flex items-center gap-1 rounded-md px-2 py-1 text-xs text-zinc-300 hover:bg-raised hover:text-zinc-100">
            <PencilSimple size={13} aria-hidden="true" /> Open in Builder
          </Link>
          <button type="button" onClick={onRemove} disabled={removing} aria-label={`Remove design ${design.slot}`}
                  className="flex h-7 w-7 items-center justify-center rounded-md text-zinc-500 hover:bg-raised hover:text-zinc-200 disabled:opacity-40">
            <Trash size={14} aria-hidden="true" />
          </button>
        </div>
        <p className="w-full text-[11px] text-zinc-500">
          Saved {formatTimestamp(design.saved_at)} · {design.architecture.services.length} services · {s.resource_count} resources
        </p>
      </header>

      <div className="grid grid-cols-2 gap-px border-b border-line bg-line">
        <div className="bg-surface px-4 py-3">
          <p className="text-xs text-zinc-500">Monthly cost</p>
          <p className={`font-mono text-2xl font-semibold tabular-nums ${cheaper ? "text-emerald-300" : "text-zinc-100"}`}>
            {usd(s.monthly_usd)}<span className="text-xs font-normal text-zinc-500">/mo</span>
          </p>
          {costDiff !== null && Math.abs(costDiff) >= 0.005 && (
            <p className="font-mono text-[11px] tabular-nums text-zinc-500">
              {formatUsd(costDiff)} vs {rival!.slot}
            </p>
          )}
        </div>
        <div className="bg-surface px-4 py-3">
          <p className="text-xs text-zinc-500">Verdict (static check)</p>
          <div className="mt-1.5"><VerdictBadge verdict={s.verdict} /></div>
          <p className={`mt-1.5 text-[11px] ${fewerRisks ? "text-emerald-300" : "text-zinc-400"}`}>
            {s.risk_count} finding{s.risk_count === 1 ? "" : "s"} · {s.blocking_count} blocking
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-2 border-b border-line px-4 py-3">
        <h3 className="text-xs font-medium text-zinc-400">Pillar scores</h3>
        <ul className="flex flex-col gap-1.5">
          {PILLARS.map((p) => {
            const score = s.pillars[p].score;
            const delta = r ? score - r.pillars[p].score : 0;
            const tone = scoreTone(score);
            const Glyph = PILLAR_META[p].icon;
            return (
              <li key={p} className="grid grid-cols-[110px_minmax(0,1fr)_44px_44px] items-center gap-2 text-xs">
                <span className="flex items-center gap-1.5 text-zinc-300">
                  <Glyph size={13} className="text-zinc-500" aria-hidden="true" />{PILLAR_META[p].label}
                </span>
                <span className="h-1.5 overflow-hidden rounded-sm bg-raised" role="meter" aria-valuemin={0} aria-valuemax={100}
                      aria-valuenow={score} aria-label={`${PILLAR_META[p].label} score of design ${design.slot}`}>
                  <span className={`block h-full ${tone.bar}`} style={{ width: `${score}%` }} />
                </span>
                <span className={`text-right font-mono font-semibold tabular-nums ${tone.text}`}>{score}</span>
                <span className={`text-right font-mono text-[11px] tabular-nums ${
                  delta > 0 ? "text-emerald-300" : delta < 0 ? "text-orange-300" : "text-zinc-600"}`}>
                  {r ? (delta > 0 ? `+${delta}` : delta < 0 ? `${delta}` : "=") : ""}
                </span>
              </li>
            );
          })}
        </ul>
        <p className="flex flex-wrap gap-x-3 font-mono text-[11px]">
          {counts.map(({ sev, n }) => (
            <span key={sev} className={n ? SEVERITY_STYLE[sev].text : "text-zinc-600"}>{n} {sev.toLowerCase()}</span>
          ))}
        </p>
      </div>

      <div className="px-4 py-3">
        <h3 className="text-xs font-medium text-zinc-400">Services</h3>
        <table className="mt-1 w-full text-left text-xs">
          <thead className="sr-only"><tr><th>Name</th><th>Type</th><th>Monthly cost</th></tr></thead>
          <tbody className="divide-y divide-line">
            {s.services.map((svc) => (
              <tr key={svc.name}>
                <td className="py-1.5 pr-2 font-mono text-zinc-200" translate="no">{svc.name}</td>
                <td className="py-1.5 pr-2 text-zinc-500">{svc.type}</td>
                <td className="py-1.5 text-right font-mono tabular-nums text-zinc-300">{usd(svc.monthly_usd)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {s.cost_note && <p className="mt-2 text-[11px] leading-relaxed text-zinc-500">{s.cost_note}</p>}
      </div>
    </section>
  );
}

function Differences({ diff }: { diff: NonNullable<Comparison["diff"]> }) {
  if (diff.identical) {
    return <p className="rounded-md border border-line bg-surface px-4 py-3 text-sm text-zinc-400">The two designs are identical: same services, same settings.</p>;
  }
  const svcList = (items: { name: string; type: string }[], slot: Slot) => (
    <div className="min-w-0 flex-1 rounded-md border border-line bg-surface">
      <h3 className="border-b border-line px-4 py-2 text-xs font-medium text-zinc-400">
        Only in Design {slot} <span className="font-mono text-zinc-500">{items.length}</span>
      </h3>
      {items.length === 0 ? <p className="px-4 py-2.5 text-xs text-zinc-500">None</p> : (
        <ul className="divide-y divide-line">
          {items.map((i) => (
            <li key={`${i.type}-${i.name}`} className="flex items-center gap-2 px-4 py-2 text-xs">
              <span className="font-mono text-zinc-200" translate="no">{i.name}</span>
              <span className="text-zinc-500">{i.type}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-col gap-3 md:flex-row">
        {svcList(diff.only_in_a, "A")}
        {svcList(diff.only_in_b, "B")}
      </div>
      <div className="overflow-hidden rounded-md border border-line bg-surface">
        <h3 className="border-b border-line px-4 py-2 text-xs font-medium text-zinc-400">
          Changed settings <span className="font-mono text-zinc-500">{diff.changed_settings.length}</span>
        </h3>
        {diff.changed_settings.length === 0 ? <p className="px-4 py-2.5 text-xs text-zinc-500">No shared service has different settings.</p> : (
          <div className="overflow-x-auto">
            <table className="w-full min-w-[520px] text-left text-xs">
              <thead>
                <tr className="border-b border-line text-zinc-500">
                  <th className="px-4 py-2 font-medium">Service</th>
                  <th className="px-4 py-2 font-medium">Setting</th>
                  <th className="px-4 py-2 font-medium">Design A</th>
                  <th className="px-4 py-2 font-medium">Design B</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {diff.changed_settings.map((c) => (
                  <tr key={`${c.service}-${c.field}`}>
                    <td className="px-4 py-2 font-mono text-zinc-200" translate="no">{c.service}<span className="ml-2 font-sans text-zinc-500">{c.type}</span></td>
                    <td className="px-4 py-2 font-mono text-zinc-400">{c.field}</td>
                    <td className="px-4 py-2 font-mono text-zinc-200" translate="no">{show(c.a)}</td>
                    <td className="px-4 py-2 font-mono text-zinc-200" translate="no">{show(c.b)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export default function ComparePage() {
  const { mode } = useMode();
  const [state, setState] = useState<{ status: "loading" } | { status: "ready"; data: Comparison } | { status: "error"; error: string }>({ status: "loading" });
  const [removing, setRemoving] = useState<Slot | null>(null);

  // fetch only; the initial state is already "loading", retry() resets it first
  const load = useCallback(() => {
    api.comparisons().then(
      (data) => setState({ status: "ready", data }),
      (err) => setState({ status: "error", error: err instanceof Error ? err.message : String(err) }),
    );
  }, []);

  useEffect(() => {
    if (mode === "live") load();
  }, [mode, load]);

  const retry = () => {
    setState({ status: "loading" });
    load();
  };

  const remove = (slot: Slot) => {
    if (!window.confirm(`Remove design ${slot}?`)) return;
    setRemoving(slot);
    api.deleteDesign(slot).then(load, (err) => setState({ status: "error", error: err instanceof Error ? err.message : String(err) }))
      .finally(() => setRemoving(null));
  };

  const data = state.status === "ready" ? state.data : null;
  const h = data?.highlights ?? null;

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-col gap-1">
        <h1 className="text-balance text-2xl font-semibold tracking-tight text-zinc-50">Compare Designs</h1>
        <p className="text-sm text-zinc-400">
          Save two designs from the Builder as A and B. Each save runs the static check (plan, OPA, graph diff, cost;
          no MiniStack apply, not signed).
        </p>
      </div>

      {mode === "demo" ? (
        <EmptyState title="Compare Needs the API" body="Saved designs live in the SimulaCrum API's SQLite database. Start the API (python -m app.server) and reload." />
      ) : state.status === "error" ? (
        <ErrorState title="Could not load the saved designs" detail={state.error}
                    hint="Check that the SimulaCrum API is running, then retry." onRetry={retry} />
      ) : !data ? (
        <div className="grid gap-4 md:grid-cols-2" aria-busy="true">
          <SkeletonBlock className="h-80" /><SkeletonBlock className="h-80" />
        </div>
      ) : (
        <>
          {h && (
            <div className="flex flex-col gap-3 md:flex-row" aria-label="Highlights">
              <Highlight icon={CurrencyDollarSimple} title="Cheaper" slot={h.cheaper.slot} reason={h.cheaper.reason} />
              <Highlight icon={ShieldCheck} title="Fewer risks" slot={h.fewer_risks.slot} reason={h.fewer_risks.reason} />
            </div>
          )}
          <div className="grid items-start gap-4 md:grid-cols-2">
            {SLOTS.map((slot) => {
              const design = data[slot];
              return design ? (
                <DesignCard key={slot} design={design} rival={data[other(slot)]}
                            cheaper={h?.cheaper.slot === slot} fewerRisks={h?.fewer_risks.slot === slot}
                            onRemove={() => remove(slot)} removing={removing === slot} />
              ) : <EmptySlot key={slot} slot={slot} />;
            })}
          </div>
          {data.diff && (
            <section aria-labelledby="differences" className="flex flex-col gap-3">
              <h2 id="differences" className="text-lg font-semibold text-zinc-100">What Differs</h2>
              <Differences diff={data.diff} />
            </section>
          )}
        </>
      )}
    </div>
  );
}
