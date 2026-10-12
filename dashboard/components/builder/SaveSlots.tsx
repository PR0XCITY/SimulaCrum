"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, FloppyDisk } from "@phosphor-icons/react";
import { api } from "@/lib/api";
import { SLOTS, type Slot } from "@/lib/compare";
import type { ArchitectureService } from "@/lib/types";
import { noFormRestore } from "@/lib/dom";

type SlotState =
  | { status: "idle" }
  | { status: "saving"; since: number }
  | { status: "saved"; forKey: string }
  | { status: "error"; error: string };

function Seconds({ since }: { since: number }) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, []);
  return <span className="font-mono tabular-nums">{Math.max(0, Math.round((now - since) / 1000))}s</span>;
}

/** "Save as A / B": runs the static check on the server and keeps the design in SQLite. */
export function SaveSlots({ architecture, archKey, disabled }: {
  architecture: { services: ArchitectureService[] }; archKey: string; disabled: boolean;
}) {
  const [state, setState] = useState<Record<Slot, SlotState>>({ A: { status: "idle" }, B: { status: "idle" } });
  const busy = SLOTS.some((s) => state[s].status === "saving");

  const save = (slot: Slot) => {
    const forKey = archKey;
    setState((prev) => ({ ...prev, [slot]: { status: "saving", since: Date.now() } }));
    api.saveDesign(slot, architecture).then(
      () => setState((prev) => ({ ...prev, [slot]: { status: "saved", forKey } })),
      (err) => setState((prev) => ({ ...prev, [slot]: { status: "error", error: err instanceof Error ? err.message : String(err) } })),
    );
  };

  const saved = SLOTS.filter((s) => { const st = state[s]; return st.status === "saved" && st.forKey === archKey; });
  const saving = SLOTS.find((s) => state[s].status === "saving");
  const failed = SLOTS.find((s) => state[s].status === "error");

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[11px] text-zinc-500" aria-live="polite">
        {saving && (() => { const st = state[saving]; return st.status === "saving" ? <>Saving as {saving}, running the static check… <Seconds since={st.since} /></> : null; })()}
        {!saving && failed && (() => { const st = state[failed]; return st.status === "error" ? <span className="text-red-300">Could not save {failed}: {st.error}</span> : null; })()}
        {!saving && !failed && saved.length > 0 && (
          <Link href="/compare" className="inline-flex items-center gap-1 text-cyan-300 hover:text-cyan-200">
            Saved as {saved.join(" and ")} · Compare <ArrowRight size={12} aria-hidden="true" />
          </Link>
        )}
      </span>
      {SLOTS.map((slot) => (
        <button {...noFormRestore} key={slot} type="button" onClick={() => save(slot)} disabled={disabled || busy}
                className="flex items-center gap-1.5 rounded-md border border-cyan-400/50 px-3 py-1.5 text-xs font-medium text-cyan-200 transition-colors duration-150 hover:bg-cyan-400/10 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-40">
          <FloppyDisk size={13} aria-hidden="true" /> Save as {slot}
        </button>
      ))}
    </div>
  );
}
