//! Shared HTTP helper for pubkey read/write URLs.

#[cfg(not(target_arch = "wasm32"))]
use std::time::Duration;

use serde_json::{json, Value};

use crate::errors::{ErrorCodes, PubkeyError};

const CONNECTION_ATTEMPTS: u32 = 4;
const CONNECTION_RETRY_DELAY_MS: u64 = 400;
const UNREACHABLE_MESSAGE: &str = "The pubkey server could not be reached.";
const HTTPS_FAILED_MESSAGE: &str =
    "The pubkey server was reached but HTTPS could not be established.";
const TIMEOUT_MESSAGE: &str = "The pubkey server did not respond in time.";

/// Synthetic body returned when a signed write is reconciled after replay.
pub fn reconciled_from_replay_response() -> Value {
    json!({
        "ok": true,
        "reconciled_from_replay": true,
    })
}

/// Join base URL (trim trailing slashes) with an absolute path.
pub fn join_url(base: &str, path: &str) -> String {
    let base = base.trim_end_matches('/');
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    format!("{base}{path}")
}

/// Thin wrapper around reqwest with shared defaults.
#[derive(Clone)]
pub struct HttpClient {
    inner: reqwest::Client,
}

impl HttpClient {
    /// Build with 30s timeouts and JSON Accept.
    pub fn new() -> Result<Self, PubkeyError> {
        let builder = reqwest::Client::builder();
        // Browser `fetch` has no connect timeout. Native builds keep both limits.
        #[cfg(not(target_arch = "wasm32"))]
        let builder = builder
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(30));
        let inner = builder.build().map_err(|e| {
            PubkeyError::new(ErrorCodes::PROVIDER_UNAVAILABLE, e.to_string())
        })?;
        Ok(Self { inner })
    }

    /// Wrap an existing reqwest client.
    pub fn from_reqwest(inner: reqwest::Client) -> Self {
        Self { inner }
    }

    /// Access the underlying client.
    pub fn inner(&self) -> &reqwest::Client {
        &self.inner
    }
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new().expect("reqwest client")
    }
}

fn classify_transport(err: &reqwest::Error) -> &'static str {
    let text = format!("{err}").to_lowercase();
    if err.is_timeout() {
        return "timeout";
    }
    if text.contains("handshake")
        || text.contains("certificate")
        || text.contains("tls")
        || text.contains("ssl")
        || text.contains("badcertificate")
    {
        return "tls";
    }
    #[cfg(not(target_arch = "wasm32"))]
    let connect_failure = err.is_connect();
    #[cfg(target_arch = "wasm32")]
    let connect_failure = false;
    if connect_failure
        || text.contains("connection failed")
        || text.contains("connection refused")
        || text.contains("connection reset")
        || text.contains("dns")
        || text.contains("failed to lookup")
        || text.contains("name resolution")
    {
        return "unreachable";
    }
    "other"
}

/// Shared HTTP helper matching Dart `pubkeyRequest`.
pub async fn pubkey_request(
    http: &HttpClient,
    url: &str,
    method: &str,
    body: Option<&Value>,
    reconcile_replay_after_connection_failure: bool,
) -> Result<Value, PubkeyError> {
    let mut had_connection_failure = false;
    let mut last_error: Option<PubkeyError> = None;

    for attempt in 1..=CONNECTION_ATTEMPTS {
        let mut builder = match method.to_uppercase().as_str() {
            "GET" => http.inner.get(url),
            "POST" => http.inner.post(url),
            "PUT" => http.inner.put(url),
            "DELETE" => http.inner.delete(url),
            other => http.inner.request(
                other
                    .parse()
                    .unwrap_or(reqwest::Method::GET),
                url,
            ),
        };
        builder = builder.header("Accept", "application/json");
        if body.is_some() {
            builder = builder.header("Content-Type", "application/json");
        }
        if let Some(b) = body {
            builder = builder.json(b);
        }

        match builder.send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let text = response.text().await.unwrap_or_default();
                let parsed: Value = if text.trim().is_empty() {
                    Value::Null
                } else {
                    serde_json::from_str(&text).unwrap_or(Value::String(text.clone()))
                };
                if !(200..300).contains(&status) {
                    let err = PubkeyError::from_response(status, &parsed);
                    if reconcile_replay_after_connection_failure
                        && had_connection_failure
                        && err.is_replay_rejection()
                    {
                        return Ok(reconciled_from_replay_response());
                    }
                    return Err(err);
                }
                return Ok(parsed);
            }
            Err(err) => {
                match classify_transport(&err) {
                    "tls" => {
                        return Err(PubkeyError::with_status(
                            ErrorCodes::HTTPS_COULD_NOT_BE_ESTABLISHED,
                            HTTPS_FAILED_MESSAGE,
                            0,
                        ));
                    }
                    "timeout" | "unreachable" => {
                        had_connection_failure = true;
                        let code = if classify_transport(&err) == "timeout" {
                            ErrorCodes::REQUEST_TIMEOUT
                        } else {
                            ErrorCodes::PUBKEY_UNREACHABLE
                        };
                        let message = if code == ErrorCodes::REQUEST_TIMEOUT {
                            TIMEOUT_MESSAGE
                        } else {
                            UNREACHABLE_MESSAGE
                        };
                        last_error = Some(PubkeyError::with_status(code, message, 0));
                        if attempt == CONNECTION_ATTEMPTS {
                            break;
                        }
                        #[cfg(feature = "native")]
                        {
                            tokio::time::sleep(Duration::from_millis(CONNECTION_RETRY_DELAY_MS))
                                .await;
                        }
                        #[cfg(not(feature = "native"))]
                        {
                            let _ = CONNECTION_RETRY_DELAY_MS;
                        }
                        continue;
                    }
                    _ => {
                        return Err(PubkeyError::new(
                            ErrorCodes::PROVIDER_UNAVAILABLE,
                            err.to_string(),
                        ));
                    }
                }
            }
        }
    }

    Err(last_error.unwrap_or_else(|| {
        PubkeyError::with_status(ErrorCodes::PUBKEY_UNREACHABLE, UNREACHABLE_MESSAGE, 0)
    }))
}
