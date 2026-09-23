import {
  Families,
  Purposes,
  selectBestArtifact,
  type Artifact,
  type Capabilities,
  type SelectPreferences,
} from "./select.js";

export type DiscoveryDocumentJson = {
  schemaVersion?: string;
  identityId?: string;
  $schema?: string;
  capabilities?: Record<string, unknown>;
  extensions?: Record<string, unknown>;
  [key: string]: unknown;
};

/**
 * Parsed Discovery Document (core schema 1.0).
 * Unknown optional fields and extensions are preserved in `raw`.
 */
export class DiscoveryDocument {
  readonly schemaVersion: string;
  readonly identityId: string;
  readonly schema: string | undefined;
  readonly capabilities: Record<string, unknown>;
  readonly extensions: Record<string, unknown>;
  readonly raw: DiscoveryDocumentJson;

  constructor(json: DiscoveryDocumentJson) {
    const caps = json.capabilities;
    const ext = json.extensions;
    this.schemaVersion = json.schemaVersion != null ? String(json.schemaVersion) : "";
    this.identityId = json.identityId != null ? String(json.identityId) : "";
    this.schema = json.$schema != null ? String(json.$schema) : undefined;
    this.capabilities =
      caps && typeof caps === "object" && !Array.isArray(caps)
        ? { ...(caps as Record<string, unknown>) }
        : {};
    this.extensions =
      ext && typeof ext === "object" && !Array.isArray(ext)
        ? { ...(ext as Record<string, unknown>) }
        : {};
    this.raw = { ...json };
  }

  static fromJson(json: DiscoveryDocumentJson): DiscoveryDocument {
    return new DiscoveryDocument(json);
  }

  get crypto(): Record<string, unknown> | null {
    const c = this.capabilities.crypto;
    return c && typeof c === "object" && !Array.isArray(c)
      ? (c as Record<string, unknown>)
      : null;
  }

  encryptionKeys(): Record<string, unknown>[] {
    const enc = this.crypto?.encryption;
    if (!enc || typeof enc !== "object" || Array.isArray(enc)) return [];
    const keys = (enc as { keys?: unknown }).keys;
    if (!Array.isArray(keys)) return [];
    return keys.filter(
      (k): k is Record<string, unknown> =>
        !!k && typeof k === "object" && !Array.isArray(k),
    );
  }

  /**
   * Project encryption keys into the artifact shape expected by
   * `selectBestArtifact` (`family` pgp|smime, catalog `algorithm`,
   * `public_material`).
   */
  encryptionArtifactsForSelection(): Artifact[] {
    const out: Artifact[] = [];
    let index = 0;
    for (const key of this.encryptionKeys()) {
      const familyRaw = key.family != null ? String(key.family) : "";
      const family = familyRaw === "openpgp" ? Families.pgp : familyRaw;
      if (family !== Families.pgp && family !== Families.smime) continue;
      const algorithms = key.algorithms;
      const algorithm =
        Array.isArray(algorithms) && algorithms.length > 0
          ? String(algorithms[0])
          : null;
      if (!algorithm) continue;
      const material =
        key.publicKey != null ? String(key.publicKey) : null;
      if (!material) continue;
      out.push({
        family,
        algorithm,
        purpose: Purposes.encryption,
        status: "active",
        key_id: index++,
        published_key_id: key.keyId,
        public_material: material,
      });
    }
    return out;
  }

  selectBestEncryptionKey(
    capabilities: Capabilities,
    preferences?: SelectPreferences,
  ): Artifact | null {
    return selectBestArtifact(
      this.encryptionArtifactsForSelection(),
      capabilities,
      preferences,
      Purposes.encryption,
    );
  }

  verificationKeys(): Record<string, unknown>[] {
    const ver = this.crypto?.verification;
    if (!ver || typeof ver !== "object" || Array.isArray(ver)) return [];
    const keys = (ver as { keys?: unknown }).keys;
    if (!Array.isArray(keys)) return [];
    return keys.filter(
      (k): k is Record<string, unknown> =>
        !!k && typeof k === "object" && !Array.isArray(k),
    );
  }

  preferredLanguages(): string[] {
    const prefs = this.capabilities.preferences;
    if (!prefs || typeof prefs !== "object" || Array.isArray(prefs)) return [];
    const languages = (prefs as { languages?: unknown }).languages;
    if (!Array.isArray(languages)) return [];
    return languages.map((l) => String(l));
  }
}
