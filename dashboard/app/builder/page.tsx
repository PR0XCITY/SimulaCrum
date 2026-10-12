"use client";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Plus } from "@phosphor-icons/react";
import { useMode } from "@/components/ModeProvider";
import { AdvisorPanel } from "@/components/builder/AdvisorPanel";
import { ArchitectureDiagram } from "@/components/builder/ArchitectureDiagram";
import { ResultsPanel, type Async } from "@/components/builder/ResultsPanel";
import { SaveSlots } from "@/components/builder/SaveSlots";
import { ServiceCard } from "@/components/builder/ServiceCard";
import { EmptyState, ErrorState, SkeletonBlock } from "@/components/states";
import { ApiError, advise, api, certify, isAbort } from "@/lib/api";
import {
  applyChanges, canApply, EXAMPLES, loadExample, newService, ownerMap, stripIndex, toArchitecture, type BuilderService,
} from "@/lib/builder";
import type {
  AdvisorResult, ArchitectureError, CatalogService, Certificate, CheckResult, ConfigChange, PreviewResult,
} from "@/lib/types";

const PREVIEW_DELAY_MS = 350;
const CHECK_DELAY_MS = 2000;

type PreviewState = { forKey: string; data?: PreviewResult; errors?: ArchitectureError[]; error?: string } | null;

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));

const PRICING_LABEL: Record<CatalogService["pricing"], string> = {
  fixed: "priced", usage_based: "usage", free: "free", unsupported: "unpriced",
};

export default function BuilderPage() {
  const { mode } = useMode();
  const [catalog, setCatalog] = useState<{ status: "loading" } | { status: "ready"; data: CatalogService[] } | { status: "error"; error: string }>({ status: "loading" });
  const [catalogAttempt, setCatalogAttempt] = useState(0);
  const [services, setServices] = useState<BuilderService[]>([]);
  const [preview, setPreview] = useState<PreviewState>(null);
  const [check, setCheck] = useState<Async<CheckResult>>({ status: "idle" });
  const [full, setFull] = useState<Async<Certificate>>({ status: "idle" });
  const [advice, setAdvice] = useState<Async<AdvisorResult>>({ status: "idle" });
  const previewCtl = useRef<AbortController | null>(null);
  const checkCtl = useRef<AbortController | null>(null);

  const architecture = useMemo(() => toArchitecture(services), [services]);
  const key = useMemo(() => JSON.stringify(architecture), [architecture]);

  // catalog
  useEffect(() => {
    if (mode !== "live") return;
    let alive = true;
    api.catalog().then(
      (data) => alive && setCatalog({ status: "ready", data }),
      (err) => alive && setCatalog({ status: "error", error: message(err) }),
    );
    return () => {
      alive = false;
    };
  }, [mode, catalogAttempt]);

  // fast preview: Terraform, validation errors, resources per service
  useEffect(() => {
    if (!services.length) return;
    const timer = setTimeout(() => {
      previewCtl.current?.abort();
      const ctl = new AbortController();
      previewCtl.current = ctl;
      api.preview(architecture, ctl.signal).then(
        (data) => setPreview({ forKey: key, data }),
        (err) => {
          if (isAbort(err)) return;
          if (err instanceof ApiError && err.errors) setPreview({ forKey: key, errors: err.errors });
          else setPreview({ forKey: key, error: message(err) });
        },
      );
    }, PREVIEW_DELAY_MS);
    return () => clearTimeout(timer);
  }, [key, architecture, services.length]);

  // debounced static check, once the preview for this exact architecture is valid
  const previewValid = preview?.forKey === key && Boolean(preview.data);
  useEffect(() => {
    if (!previewValid) return;
    const timer = setTimeout(() => {
      checkCtl.current?.abort();
      const ctl = new AbortController();
      checkCtl.current = ctl;
      setCheck({ status: "running", startedAt: Date.now(), forKey: key });
      api.check(architecture, ctl.signal).then(
        (data) => setCheck({ status: "ready", data, forKey: key }),
        (err) => {
          if (!isAbort(err)) setCheck({ status: "error", error: message(err), forKey: key });
        },
      );
    }, CHECK_DELAY_MS);
    return () => clearTimeout(timer);
  }, [previewValid, key, architecture]);

  // Certify runs as a background job on the API; poll it so no request has to stay open for minutes.
  const unmounted = useRef(false);
  useEffect(() => {
    unmounted.current = false; // React dev mode mounts twice: reset on every mount
    return () => {
      unmounted.current = true;
    };
  }, []);
  const runFull = useCallback(() => {
    const forKey = key;
    const startedAt = Date.now();
    setFull({ status: "running", startedAt, forKey });
    certify(architecture, (job) => {
      const note = job.status === "queued" && job.queue_position
        ? `Waiting for ${job.queue_position} other certification${job.queue_position === 1 ? "" : "s"} to finish first.`
        : undefined;
      if (!unmounted.current) setFull({ status: "running", startedAt, forKey, note });
    }, () => unmounted.current).then(
      (data) => !unmounted.current && setFull({ status: "ready", data, forKey }),
      (err) => !unmounted.current && !isAbort(err) && setFull({ status: "error", error: message(err), forKey }),
    );
  }, [architecture, key]);

  // Trusted Advisor: also a background job (it plans and prices every candidate change).
  const runAdvisor = useCallback(() => {
    const forKey = key;
    const startedAt = Date.now();
    setAdvice({ status: "running", startedAt, forKey });
    advise(architecture, (job) => {
      const note = job.status === "queued" && job.queue_position ? "Waiting for another advisor run to finish first." : undefined;
      if (!unmounted.current) setAdvice({ status: "running", startedAt, forKey, note });
    }, () => unmounted.current).then(
      (data) => !unmounted.current && setAdvice({ status: "ready", data, forKey }),
      (err) => !unmounted.current && !isAbort(err) && setAdvice({ status: "error", error: message(err), forKey }),
    );
  }, [architecture, key]);

  const entries = useMemo(() => (catalog.status === "ready" ? catalog.data : []), [catalog]);
  const byType = useMemo(() => Object.fromEntries(entries.map((e) => [e.type, e])), [entries]);
  const labels = useMemo(() => Object.fromEntries(entries.map((e) => [e.type, e.label])), [entries]);

  const addService = (entry: CatalogService) => {
    const taken = new Set(services.map((s) => String(s.config.name)));
    setServices((prev) => [...prev, newService(entry, taken)]);
  };

  const replaceWith = (next: BuilderService[], what: string) => {
    if (services.length && !window.confirm(`Replace the current ${services.length} service(s) with ${what}?`)) return;
    setServices(next);
  };

  // /builder?load=A|B opens a design saved for comparison
  const [loadError, setLoadError] = useState<string | null>(null);
  const loadedSlot = useRef(false);
  useEffect(() => {
    if (catalog.status !== "ready" || loadedSlot.current) return;
    const slot = new URLSearchParams(window.location.search).get("load");
    if (slot !== "A" && slot !== "B") return;
    loadedSlot.current = true;
    api.comparisons().then((cmp) => {
      const design = cmp[slot];
      if (!design) return setLoadError(`Slot ${slot} is empty.`);
      const taken = new Set<string>();
      setServices(design.architecture.services.map((spec) => {
        const entry = catalog.data.find((c) => c.type === spec.type);
        if (!entry) throw new Error(`catalog has no ${spec.type}`);
        const s = newService(entry, taken, { config: spec.config, usage: spec.usage ?? {} });
        taken.add(String(s.config.name));
        return s;
      }));
    }).catch((err) => setLoadError(`Could not load slot ${slot}: ${message(err)}`));
  }, [catalog]);

  const onApplyFix = (changes: ConfigChange[]) => {
    setServices((prev) => applyChanges(prev, changes) ?? prev);
  };

  // derived view state
  const latestPreview = preview?.data ? preview : null; // keep showing the last valid preview while typing
  const invalid = preview?.forKey === key && Boolean(preview.errors?.length);
  const fieldErrors = useMemo(() => {
    const map: Record<number, Record<string, string>> = {};
    if (preview?.forKey === key) {
      for (const e of preview.errors ?? []) {
        if (typeof e.service === "number") (map[e.service] ??= {})[e.field] = e.message;
      }
    }
    return map;
  }, [preview, key]);
  const previewServices = useMemo(() => latestPreview?.data?.services ?? [], [latestPreview]);
  const owners = useMemo(() => ownerMap(previewServices), [previewServices]);
  const fullFresh = full.status === "ready" && full.forKey === key;
  const checkFresh = check.status === "ready" && check.forKey === key;
  const riskyResources = useMemo(() => {
    const graph = fullFresh && full.status === "ready" ? full.data.blast_radius
      : check.status === "ready" ? check.data : null;
    const set = new Set<string>();
    if (!graph) return set;
    // Red = blocking only (design rule): resources with a CRITICAL/HIGH flag, not MEDIUM warnings.
    graph.risk_flags.filter((f) => f.severity === "CRITICAL" || f.severity === "HIGH")
      .forEach((f) => set.add(stripIndex(f.resource)));
    return set;
  }, [full, check, fullFresh]);
  const graphEdges = check.status === "ready" ? check.data.graph.edges : [];
  const flaggedServices = new Set([...riskyResources].map((r) => owners.get(r)).filter(Boolean) as string[]);

  if (mode === "demo") {
    return (
      <div className="flex flex-col gap-4">
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">Architecture Builder</h1>
        <ErrorState title="The builder needs the live API"
                    detail="Demo mode: the GhostOps API is not reachable, and every change here is generated and analysed by it."
                    hint="Start it with python -m app.server, then reload. The sample certificates are still on the Certificates page." />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-5">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div className="flex flex-col gap-1">
          <h1 className="text-balance text-2xl font-semibold tracking-tight text-zinc-50">Architecture Builder</h1>
          <p className="text-sm text-zinc-400">
            Compose services, see the Terraform, risks and cost as you edit, then Certify it to run the full check and save it to Certificates.
          </p>
        </div>
        {services.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <SaveSlots architecture={architecture} archKey={key} disabled={invalid || mode !== "live"} />
            <button type="button" onClick={() => window.confirm("Remove all services?") && setServices([])}
                    className="rounded-md border border-line-strong px-3 py-1.5 text-xs text-zinc-300 transition-colors duration-150 hover:bg-raised">
              Clear All
            </button>
          </div>
        )}
      </div>
      {loadError && <p role="alert" className="text-xs text-red-300">{loadError}</p>}

      <div className="grid gap-4 lg:grid-cols-[210px_minmax(0,1fr)] xl:grid-cols-[210px_minmax(0,1fr)_400px]">
        {/* palette */}
        <nav aria-label="Service palette" className="flex min-w-0 flex-col gap-4">
          <div className="rounded-md border border-line bg-surface">
            <h2 className="border-b border-line px-3 py-2 text-xs font-medium text-zinc-400">Load Example</h2>
            <div className="flex flex-col gap-1.5 p-2">
              {(Object.keys(EXAMPLES) as ("risky" | "safe")[]).map((name) => (
                <button key={name} type="button" disabled={catalog.status !== "ready"}
                        onClick={() => catalog.status === "ready" && replaceWith(loadExample(name, catalog.data), EXAMPLES[name].label)}
                        className={`rounded-md border px-2.5 py-1.5 text-left text-xs transition-colors duration-150 disabled:opacity-40 ${
                          name === "risky" ? "border-red-500/40 text-red-200 hover:bg-red-500/10" : "border-emerald-500/40 text-emerald-200 hover:bg-emerald-500/10"
                        }`}>
                  {EXAMPLES[name].label}
                </button>
              ))}
            </div>
          </div>
          <div className="rounded-md border border-line bg-surface">
            <h2 className="border-b border-line px-3 py-2 text-xs font-medium text-zinc-400">Services</h2>
            {catalog.status === "loading" && <div className="flex flex-col gap-2 p-2">{[0, 1, 2, 3].map((i) => <SkeletonBlock key={i} className="h-10" />)}</div>}
            {catalog.status === "error" && (
              <div className="p-2">
                <ErrorState title="Catalog unavailable" detail={catalog.error} hint="Check the API, then retry."
                            onRetry={() => { setCatalog({ status: "loading" }); setCatalogAttempt((n) => n + 1); }} />
              </div>
            )}
            {catalog.status === "ready" && (
              <ul className="divide-y divide-line">
                {catalog.data.map((entry) => (
                  <li key={entry.type}>
                    <button type="button" onClick={() => addService(entry)} title={entry.description}
                            className="group flex w-full items-center gap-2 px-3 py-2 text-left transition-colors duration-150 hover:bg-raised">
                      <Plus size={13} className="shrink-0 text-cyan-400" aria-hidden="true" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm text-zinc-200">{entry.label}</span>
                        <span className="block font-mono text-[10px] text-zinc-500">
                          {entry.shadow_supported ? "shadow" : "static only"} · {PRICING_LABEL[entry.pricing]}
                        </span>
                      </span>
                      <span className="sr-only">Add {entry.label}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </nav>

        {/* canvas */}
        <div className="flex min-w-0 flex-col gap-4">
          <section className="min-w-0 overflow-hidden rounded-md border border-line bg-surface" aria-label="Architecture diagram">
            <h2 className="border-b border-line px-4 py-2.5 text-sm font-medium text-zinc-300">Diagram</h2>
            <ArchitectureDiagram services={services.length ? previewServices : []} labels={labels}
                                 riskyResources={riskyResources} edges={graphEdges} />
          </section>
          {services.length === 0 ? (
            <div className="rounded-md border border-dashed border-line-strong">
              <EmptyState title="No Services Yet"
                          body="Add a service from the palette, or load the risky or safe example to see how GhostOps reacts." />
            </div>
          ) : (
            <div className="grid min-w-0 gap-3 2xl:grid-cols-2">
              {services.map((s, i) => byType[s.type] && (
                <ServiceCard key={s.id} service={s} entry={byType[s.type]} errors={fieldErrors[i] ?? {}}
                             flagged={flaggedServices.has(String(s.config.name))}
                             onChange={(next) => setServices((prev) => prev.map((p) => (p.id === s.id ? next : p)))}
                             onRemove={() => setServices((prev) => prev.filter((p) => p.id !== s.id))} />
              ))}
            </div>
          )}
          {services.length > 0 && (
            <AdvisorPanel state={advice} stale={advice.status === "ready" && advice.forKey !== key}
                          disabled={invalid || !previewValid} onAsk={runAdvisor} onApply={onApplyFix}
                          canApply={(changes) => canApply(services, changes)} />
          )}
          {preview?.forKey === key && preview.error && (
            <ErrorState title="Preview failed" detail={preview.error} hint="Check that the API is running." />
          )}
        </div>

        {/* results */}
        <div className="min-w-0 lg:col-span-2 xl:col-span-1">
          <div className="xl:sticky xl:top-[72px]">
            <ResultsPanel
              hasServices={services.length > 0}
              invalid={invalid}
              check={check}
              full={full}
              terraform={latestPreview?.data?.terraform ?? null}
              previewServices={previewServices}
              owners={owners}
              checkFresh={checkFresh}
              fullFresh={fullFresh}
              onAnalyze={runFull}
              onApply={onApplyFix}
              canApply={(changes) => canApply(services, changes)}
            />
            <p className="mt-2 text-[11px] leading-relaxed text-zinc-500">
              Quick checks run automatically a moment after you stop editing (not saved). Certify runs the full
              pipeline, including the MiniStack apply, and stores a signed certificate on the{" "}
              <Link href="/" className="text-cyan-300 hover:text-cyan-200">Certificates</Link> page.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
