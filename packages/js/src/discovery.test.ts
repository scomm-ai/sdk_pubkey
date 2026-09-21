import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import {
  DiscoveryDocument,
  DiscoveryError,
  createDiscoveryClient,
  encodeMailboxPath,
  Families,
} from "./index.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "../../..");
const discoveryFixtures = join(root, "conformance/fixtures/discovery");

function loadJson(name: string): unknown {
  return JSON.parse(
    readFileSync(join(discoveryFixtures, name), "utf8"),
  ) as unknown;
}

describe("DiscoveryDocument", () => {
  it("preserves unknown extensions", () => {
    const doc = DiscoveryDocument.fromJson({
      schemaVersion: "1.0",
      mailbox: "alice@example.com",
      capabilities: {
        crypto: {
          encryption: { keys: [{ family: "openpgp", keyId: "1" }] },
          verification: { keys: [{ family: "openpgp", keyId: "2" }] },
        },
      },
      extensions: {
        "https://example.org/discovery/appointment/v1": { bookingRequired: true },
      },
      futureRoot: true,
    });
    assert.equal(doc.encryptionKeys().length, 1);
    assert.equal(doc.verificationKeys().length, 1);
    assert.equal(doc.raw.futureRoot, true);
    assert.ok(
      doc.extensions["https://example.org/discovery/appointment/v1"],
    );
  });

  it("parses mailbox-discovery fixture", () => {
    const json = loadJson("mailbox-discovery.json") as Record<string, unknown>;
    const doc = DiscoveryDocument.fromJson(json);
    assert.equal(doc.schemaVersion, "1.0");
    assert.equal(doc.mailbox, "alice@example.com");
    assert.ok(doc.encryptionKeys().length > 0);
    assert.equal(doc.verificationKeys().length, 0);
  });
});

describe("encryption selection", () => {
  function dualPublishDoc(): DiscoveryDocument {
    return DiscoveryDocument.fromJson({
      schemaVersion: "1.0",
      mailbox: "alice@example.com",
      capabilities: {
        crypto: {
          encryption: {
            keys: [
              {
                family: "openpgp",
                keyId: "AAAA-0001",
                publicKey: "classical-material",
                algorithms: ["openpgp-cv25519"],
              },
              {
                family: "openpgp",
                keyId: "BBBB-0002",
                publicKey: "pqc-material",
                algorithms: ["openpgp-mlkem768-x25519"],
              },
            ],
          },
        },
      },
    });
  }

  it("classical-only sender gets cv25519, not PQC", () => {
    const selected = dualPublishDoc().selectBestEncryptionKey({
      families: { pgp: ["openpgp-cv25519"] },
    });
    assert.ok(selected);
    assert.equal(selected!.algorithm, "openpgp-cv25519");
    assert.equal(selected!.public_material, "classical-material");
    assert.equal(selected!.published_key_id, "AAAA-0001");
  });

  it("PQC-capable sender prefers ML-KEM over classical", () => {
    const selected = dualPublishDoc().selectBestEncryptionKey({
      families: {
        pgp: ["openpgp-cv25519", "openpgp-mlkem768-x25519"],
      },
    });
    assert.ok(selected);
    assert.equal(selected!.algorithm, "openpgp-mlkem768-x25519");
    assert.equal(selected!.public_material, "pqc-material");
  });

  it("unsupported families yield null", () => {
    const selected = dualPublishDoc().selectBestEncryptionKey({
      families: { smime: ["smime-rsa-oaep-sha256"] },
    });
    assert.equal(selected, null);
  });

  it("maps openpgp family token to wire pgp", () => {
    const artifacts = dualPublishDoc().encryptionArtifactsForSelection();
    assert.equal(artifacts.length, 2);
    assert.ok(artifacts.every((a) => a.family === Families.pgp));
  });
});

describe("mailbox path encoding", () => {
  it("encodes canonical mailbox with @ and +", () => {
    const encoded = encodeMailboxPath("Alice+tag@Example.COM");
    assert.ok(encoded.includes("%40"));
    assert.ok(!encoded.toLowerCase().includes("+"));
    assert.ok(encoded.includes("%2B") || encoded.includes("alice"));
  });
});

describe("DiscoveryClient", () => {
  it("requires readBaseUrl", () => {
    assert.throws(
      () => createDiscoveryClient({ readBaseUrl: "" }),
      (err: unknown) =>
        err instanceof DiscoveryError && err.code === "missing_host",
    );
  });

  it("discoverMailbox GETs /v1/mailboxes/{mailbox}", async () => {
    const fixture = loadJson("mailbox-discovery.json");
    const client = createDiscoveryClient({
      readBaseUrl: "https://discovery.test",
      fetch: async (input) => {
        const url = String(input);
        assert.ok(url.includes("/v1/mailboxes/"));
        assert.ok(url.includes("alice%40example.com") || url.includes("alice"));
        return new Response(JSON.stringify(fixture), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      },
    });
    const doc = await client.discoverMailbox("alice@example.com");
    assert.equal(doc.mailbox, "alice@example.com");
  });

  it("signing-vectors fixture is present for Dart/server parity gate", () => {
    const fixture = loadJson("signing-vectors.json") as {
      vectors: Array<{ payload_sha256: string; canonical_utf8: string }>;
    };
    assert.ok(Array.isArray(fixture.vectors));
    assert.ok(fixture.vectors[0]?.payload_sha256);
    assert.ok(fixture.vectors[0]?.canonical_utf8);
  });
});
