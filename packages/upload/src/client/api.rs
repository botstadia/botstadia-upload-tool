//! The api client: typed endpoints from `botstadia-shared`, over `ureq`.

use anyhow::{Context, Result, bail};
use botstadia_shared::api::{Endpoint, Method};

use super::Settings;

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// Call an api endpoint with the api key.
pub fn call<E: Endpoint>(settings: &Settings, body: &E::Req) -> Result<E::Res> {
    let url = format!("{}{}", settings.api_url(), E::PATH);
    let key = settings.api_key()?;
    let result = match E::METHOD {
        Method::Get => agent()
            .get(&url)
            .header("Authorization", &format!("Bearer {key}"))
            .call(),
        Method::Post => agent()
            .post(&url)
            .header("Authorization", &format!("Bearer {key}"))
            .header("Content-Type", "application/json")
            .header("Origin", &settings.api_url())
            .send(serde_json::to_vec(body)?),
    };
    read(result, &url)
}

/// Call a public endpoint (no credential).
pub fn call_public<E: Endpoint>(settings: &Settings, body: &E::Req) -> Result<E::Res> {
    let url = format!("{}{}", settings.api_url(), E::PATH);
    let result = match E::METHOD {
        Method::Get => agent().get(&url).call(),
        Method::Post => agent()
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Origin", &settings.api_url())
            .send(serde_json::to_vec(body)?),
    };
    read(result, &url)
}

fn read<T: serde::de::DeserializeOwned>(
    result: Result<ureq::http::Response<ureq::Body>, ureq::Error>,
    url: &str,
) -> Result<T> {
    match result {
        Ok(mut response) => {
            let status = response.status().as_u16();
            let text = response.body_mut().read_to_string()?;
            if status >= 400 {
                // The api's typed error says what to do about it.
                match serde_json::from_str::<botstadia_shared::error::ApiError>(&text) {
                    Ok(err) => bail!("{err}"),
                    Err(_) => bail!("{url} refused it (HTTP {status}): {text}"),
                }
            }
            serde_json::from_str(&text).with_context(|| format!("{url} answered {text}"))
        }
        Err(e) => bail!("couldn't reach {url}: {e}"),
    }
}
