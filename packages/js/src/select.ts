/** Wire families on Discovery artifacts (not document `openpgp` token). */
export const Families = {
  pgp: "pgp",
  smime: "smime",
} as const;

export const Purposes = {
  encryption: "encryption",
  signing: "signing",
  masterSigning: "master_signing",
} as const;

const WIRE_FAMILIES = new Set([Families.pgp, Families.smime]);

export type Capabilities = {
  families?: Record<string, string[] | undefined>;
};

export type SelectPreferences = {
  preferred_family?: string;
  preferred_algorithm?: string;
};

export type Artifact = {
  family: string;
  algorithm: string;
  purpose?: string;
  status?: string;
  key_id?: number | string;
  published_key_id?: unknown;
  public_material?: string | null;
  [key: string]: unknown;
};

function isPqAlgorithm(algorithm: unknown): boolean {
  const name = String(algorithm ?? "").toLowerCase();
  return (
    name.includes("mlkem") ||
    name.includes("mldsa") ||
    name.includes("slhdsa") ||
    name.includes("hqc") ||
    name.startsWith("pqc-")
  );
}

export function algorithmPreferenceRank(algorithm: unknown): number {
  return isPqAlgorithm(algorithm) ? 1 : 0;
}

export function familyPreferenceRank(family: unknown): number {
  if (family === Families.smime) return 1;
  if (family === Families.pgp) return 0;
  return -1;
}

function asInt(value: unknown): number {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  const n = Number.parseInt(String(value ?? ""), 10);
  return Number.isFinite(n) ? n : 0;
}

/**
 * Select the best mutually supported artifact.
 * Families on the wire are pgp and smime only. PQ is an algorithm property.
 * Must match Dart `selectBestArtifact` / pubkey `select.ts`.
 */
export function selectBestArtifact(
  artifacts: Artifact[],
  capabilities: Capabilities | null | undefined,
  preferences: SelectPreferences | null | undefined = {},
  purpose?: string,
): Artifact | null {
  const supported = new Set<string>();
  const families = capabilities?.families ?? {};
  for (const [family, algos] of Object.entries(families)) {
    if (!WIRE_FAMILIES.has(family as (typeof Families)[keyof typeof Families])) {
      continue;
    }
    for (const algo of algos ?? []) {
      supported.add(`${family}:${algo}`);
    }
  }

  const candidates = artifacts.filter((artifact) => {
    if (artifact.status && artifact.status !== "active") return false;
    if (
      artifact.public_material != null &&
      artifact.public_material.length === 0
    ) {
      return false;
    }
    if (!WIRE_FAMILIES.has(artifact.family as (typeof Families)[keyof typeof Families])) {
      return false;
    }
    if (purpose && artifact.purpose && artifact.purpose !== purpose) {
      return false;
    }
    return supported.has(`${artifact.family}:${artifact.algorithm}`);
  });
  if (candidates.length === 0) return null;

  const preferredFamily = preferences?.preferred_family;
  const preferredAlgorithm = preferences?.preferred_algorithm;
  if (
    preferredFamily &&
    WIRE_FAMILIES.has(preferredFamily as (typeof Families)[keyof typeof Families])
  ) {
    const preferred = candidates.find(
      (artifact) =>
        artifact.family === preferredFamily &&
        (!preferredAlgorithm || artifact.algorithm === preferredAlgorithm),
    );
    if (preferred) return preferred;
  }

  candidates.sort((a, b) => {
    const pq =
      algorithmPreferenceRank(b.algorithm) - algorithmPreferenceRank(a.algorithm);
    if (pq !== 0) return pq;
    const family =
      familyPreferenceRank(b.family) - familyPreferenceRank(a.family);
    if (family !== 0) return family;
    return asInt(b.key_id) - asInt(a.key_id);
  });
  return candidates[0] ?? null;
}
