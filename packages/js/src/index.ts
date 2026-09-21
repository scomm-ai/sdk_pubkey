export {
  createDiscoveryClient,
  DiscoveryClient,
  type DiscoveryClientOptions,
  normalizeEmail,
  encodeMailboxPath,
  joinUrl,
  DiscoveryError,
} from "./client.js";
export {
  DiscoveryDocument,
  type DiscoveryDocumentJson,
} from "./document.js";
export {
  Families,
  Purposes,
  selectBestArtifact,
  algorithmPreferenceRank,
  familyPreferenceRank,
  type Artifact,
  type Capabilities,
  type SelectPreferences,
} from "./select.js";
