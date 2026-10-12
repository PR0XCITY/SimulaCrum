import type { Severity, SignatureAlg } from "./types";
import { SEVERITIES } from "./types";

const usd = new Intl.NumberFormat(undefined, {
  style: "currency", currency: "USD", currencyDisplay: "narrowSymbol", signDisplay: "exceptZero",
  minimumFractionDigits: 2, maximumFractionDigits: 2,
});

const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
});

export function formatUsd(value: number | null): string {
  return value === null ? "n/a" : usd.format(value);
}

export function formatTimestamp(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? iso : dateTime.format(date);
}

export function signatureAlgLabel(alg: SignatureAlg | undefined): string {
  return alg === "ed25519" ? "Ed25519" : "HMAC-SHA256"; // no field: signed before Ed25519 existed
}

export function shortHash(hash: string, length = 12): string {
  return hash.length > length ? hash.slice(0, length) : hash;
}

export function topSeverity(counts: Record<Severity, number>): Severity | null {
  return SEVERITIES.find((s) => counts[s] > 0) ?? null;
}

export function resourceType(address: string): string {
  const parts = address.split(".").map((p) => p.split("[")[0]);
  while (parts.length >= 2 && parts[0] === "module") parts.splice(0, 2);
  return parts[0] ?? address;
}
