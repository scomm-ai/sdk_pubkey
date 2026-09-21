import { DiscoveryDocument } from "./document.js";
import {
  DiscoveryError,
  encodeMailboxPath,
  joinUrl,
  normalizeEmail,
} from "./http.js";

export type DiscoveryClientOptions = {
  /** Public Discovery read host (e.g. https://discovery.scomm.ai). Required. */
  readBaseUrl: string;
  /** Optional fetch implementation (defaults to global fetch). */
  fetch?: typeof fetch;
};

/**
 * Track A Discovery client: public document fetch + local key select helpers
 * on {@link DiscoveryDocument}.
 */
export class DiscoveryClient {
  readonly readBaseUrl: string;
  private readonly fetchImpl: typeof fetch;

  constructor(options: DiscoveryClientOptions) {
    const base = (options.readBaseUrl ?? "").trim();
    if (!base) {
      throw new DiscoveryError(
        "missing_host",
        "readBaseUrl is required; there is no silent production host default",
      );
    }
    this.readBaseUrl = base.replace(/\/+$/, "");
    this.fetchImpl = options.fetch ?? globalThis.fetch.bind(globalThis);
  }

  encodeMailboxPath(mailbox: string): string {
    return encodeMailboxPath(mailbox);
  }

  async discoverMailbox(mailbox: string): Promise<DiscoveryDocument> {
    const path = `/v1/mailboxes/${encodeMailboxPath(mailbox)}`;
    const url = joinUrl(this.readBaseUrl, path);
    const res = await this.fetchImpl(url, {
      method: "GET",
      headers: { Accept: "application/json" },
    });
    const text = await res.text();
    let body: unknown = null;
    if (text) {
      try {
        body = JSON.parse(text) as unknown;
      } catch {
        throw new DiscoveryError(
          "invalid_json",
          "Discovery document response was not JSON",
          { status: res.status },
        );
      }
    }
    if (!res.ok) {
      throw DiscoveryError.fromResponse(res.status, body);
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new DiscoveryError(
        "invalid_response",
        "Discovery document response was not a JSON object",
        { status: res.status },
      );
    }
    return DiscoveryDocument.fromJson(body as Record<string, unknown>);
  }
}

export function createDiscoveryClient(
  options: DiscoveryClientOptions,
): DiscoveryClient {
  return new DiscoveryClient(options);
}

export { normalizeEmail, encodeMailboxPath, joinUrl, DiscoveryError };
