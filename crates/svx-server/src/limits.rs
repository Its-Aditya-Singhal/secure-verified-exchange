//! Abuse limits: how much one network address or one account may ask of
//! the service. Counters are in memory (one process); a restart resets them.
//!
//! Behind a proxy every connection comes from the proxy, so the client's
//! address is read from a header the proxy sets (`--client-ip-header`, e.g.
//! Cloudflare's `CF-Connecting-IP`). Only set that flag when the firewall
//! admits nothing but the proxy: anyone who can connect directly can put any
//! address in the header.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use axum::extract::{ConnectInfo, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::AppState;
use crate::error::{ApiError, ApiResult};

pub const MINUTE: i64 = 60;
pub const HOUR: i64 = 3600;
pub const DAY: i64 = 24 * 3600;

/// The limits, per window. [`Limits::default`] is what production uses.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Every request from one address, per minute. Generous: a campus or
    /// hostel shares one address, and the app polls every 3 s while waiting
    /// for an approval.
    pub requests_per_ip_per_min: u32,
    /// Emailed codes asked for from one address, per hour.
    pub codes_per_ip_per_hour: u32,
    /// New personal accounts from one address, per day.
    pub accounts_per_ip_per_day: u32,
    /// Company organization registrations from one address, per day.
    pub orgs_per_ip_per_day: u32,
    /// Registry and service record lookups from one address, per minute
    /// (a changed record costs an SLH-DSA signature).
    pub registry_per_ip_per_min: u32,
    /// Files one account registers, per day.
    pub files_per_account_per_day: u32,
    /// Personal releases (opens and approval polling) by one account, per minute.
    pub releases_per_account_per_min: u32,
    /// Share requests by one account, per hour.
    pub shares_per_account_per_hour: u32,
    /// Emails the service sends in a day (codes and notifications), kept
    /// under the mail provider's daily limit (Gmail: about 500).
    pub emails_per_day: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            requests_per_ip_per_min: 600,
            codes_per_ip_per_hour: 20,
            accounts_per_ip_per_day: 20,
            orgs_per_ip_per_day: 5,
            registry_per_ip_per_min: 120,
            files_per_account_per_day: 200,
            releases_per_account_per_min: 60,
            shares_per_account_per_hour: 20,
            emails_per_day: 450,
        }
    }
}

/// The client's address (IPv6 reduced to its /64, which one user
/// typically controls in full).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientIp(pub IpAddr);

impl ClientIp {
    fn new(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => ClientIp(IpAddr::V4(v4)),
                None => {
                    let s = v6.segments();
                    ClientIp(IpAddr::V6(Ipv6Addr::new(
                        s[0], s[1], s[2], s[3], 0, 0, 0, 0,
                    )))
                }
            },
            v4 => ClientIp(v4),
        }
    }
}

pub const TOO_MANY: &str = "too many requests from your network; try again in a few minutes";
pub const TOO_MANY_ACCOUNT: &str = "too many requests from this account; try again later";

fn client_ip(st: &AppState, req: &Request) -> Option<ClientIp> {
    if let Some(name) = &st.client_ip_header
        && let Some(ip) = req
            .headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    {
        return Some(ClientIp::new(ip));
    }
    req.extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| ClientIp::new(c.0.ip()))
}

/// Middleware: find the client's address, apply the per-address request
/// limit, and leave the address in the request for the handlers.
pub async fn per_ip(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    if let Some(ip) = client_ip(&st, &req) {
        if !st.limiter.allow_in(
            &format!("req:{}", ip.0),
            st.limits.requests_per_ip_per_min,
            MINUTE,
        ) {
            return ApiError::TooMany(TOO_MANY.into()).into_response();
        }
        req.extensions_mut().insert(ip);
    }
    next.run(req).await
}

/// Count one `what` for the client's address; refuse when over `limit` in
/// `window` seconds. Without a known address there is nothing to count.
pub(crate) fn check_ip(
    st: &AppState,
    ip: Option<ClientIp>,
    what: &str,
    limit: u32,
    window: i64,
) -> ApiResult<()> {
    match ip {
        Some(ip)
            if !st
                .limiter
                .allow_in(&format!("{what}:{}", ip.0), limit, window) =>
        {
            Err(ApiError::TooMany(TOO_MANY.into()))
        }
        _ => Ok(()),
    }
}

/// Count one `what` for an account; `true` while within `limit`.
pub(crate) fn account_allows(
    st: &AppState,
    org_id: &str,
    what: &str,
    limit: u32,
    window: i64,
) -> bool {
    st.limiter
        .allow_in(&format!("{what}:{org_id}"), limit, window)
}

/// Take one email from today's budget; `false` once it is used up.
pub(crate) fn email_budget(st: &AppState) -> bool {
    st.limiter.allow_in("emails", st.limits.emails_per_day, DAY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv6_is_counted_per_64() {
        let a = ClientIp::new("2001:db8:1:2:aaaa::1".parse().unwrap());
        let b = ClientIp::new("2001:db8:1:2:bbbb::9".parse().unwrap());
        let c = ClientIp::new("2001:db8:1:3::1".parse().unwrap());
        assert_eq!(a, b);
        assert_ne!(a, c);
        let mapped = ClientIp::new("::ffff:192.0.2.7".parse().unwrap());
        assert_eq!(mapped.0, "192.0.2.7".parse::<IpAddr>().unwrap());
    }
}
