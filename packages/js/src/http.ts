/**
 * Mailbox canonicalization aligned with Dart `normalizeEmail`:
 * NFC + lowercase local@domain; `+` tags are identity-significant.
 */
export function normalizeEmail(email: string | null | undefined): string {
  if (email == null) return "";
  const trimmed = email.trim().normalize("NFC");
  const at = trimmed.lastIndexOf("@");
  if (at <= 0 || at === trimmed.length - 1) {
    return trimmed.toLowerCase().normalize("NFC");
  }
  const local = trimmed.slice(0, at).toLowerCase().normalize("NFC");
  const domain = trimmed.slice(at + 1).toLowerCase().normalize("NFC");
  return `${local}@${domain}`;
}

export async function mailboxSha256Hex(email: string): Promise<string> {
  const canonical = normalizeEmail(email);
  const bytes = new TextEncoder().encode(canonical);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function joinUrl(base: string, path: string): string {
  const b = base.replace(/\/+$/, "");
  const p = path.startsWith("/") ? path : `/${path}`;
  return `${b}${p}`;
}

export class DiscoveryError extends Error {
  readonly code: string;
  readonly status: number | undefined;
  readonly details: unknown;

  constructor(
    code: string,
    message: string,
    options?: { status?: number; details?: unknown },
  ) {
    super(message);
    this.name = "DiscoveryError";
    this.code = code;
    this.status = options?.status;
    this.details = options?.details;
  }

  static fromResponse(status: number, body: unknown): DiscoveryError {
    if (body && typeof body === "object" && !Array.isArray(body)) {
      const err = (body as { error?: unknown }).error;
      if (err && typeof err === "object" && !Array.isArray(err)) {
        const e = err as { code?: unknown; message?: unknown; details?: unknown };
        return new DiscoveryError(
          e.code != null ? String(e.code) : "http_error",
          e.message != null ? String(e.message) : `HTTP ${status}`,
          { status, details: e.details },
        );
      }
    }
    return new DiscoveryError("http_error", `HTTP ${status}`, { status, details: body });
  }
}
