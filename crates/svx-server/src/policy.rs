//! Policy evaluation. Pure and default-deny.

use svx_oidc::Identity;
use svx_protocol::Policy;

/// Why access was denied (audit detail; clients only see a coarse reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Deny {
    NotInPolicy,
    AssuranceTooLow,
    OutsideWindow,
    Expired,
}

impl Deny {
    pub fn as_str(self) -> &'static str {
        match self {
            Deny::NotInPolicy => "user not permitted by policy",
            Deny::AssuranceTooLow => "authentication assurance too low",
            Deny::OutsideWindow => "outside policy time window",
            Deny::Expired => "artifact expired",
        }
    }
}

/// Facts about the artifact taken from its *verified* header.
#[derive(Clone, Copy, Debug)]
pub struct ArtifactTimes {
    pub created_at: i64,
    pub expires_at: Option<i64>,
}

/// Evaluate `policy` for `who` at `now` (the server's clock).
///
/// Expiry is `min(signed expires_at, created_at + max_age_secs)`: the
/// recipient can shorten the sender's expiry but never extend it.
pub fn evaluate(policy: &Policy, who: &Identity, art: ArtifactTimes, now: i64) -> Result<(), Deny> {
    if art.expires_at.is_some_and(|e| now >= e) {
        return Err(Deny::Expired);
    }
    if let Some(max) = policy.max_age_secs
        && now.saturating_sub(art.created_at) > max
    {
        return Err(Deny::Expired);
    }
    let user_ok = policy.allow_users.contains(&who.sub)
        || who.groups.iter().any(|g| policy.allow_groups.contains(g));
    if !user_ok {
        return Err(Deny::NotInPolicy);
    }
    if !policy.require_acr.is_empty()
        && !who
            .acr
            .as_ref()
            .is_some_and(|a| policy.require_acr.contains(a))
    {
        return Err(Deny::AssuranceTooLow);
    }
    if policy.not_before.is_some_and(|t| now < t) || policy.not_after.is_some_and(|t| now >= t) {
        return Err(Deny::OutsideWindow);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who(sub: &str, groups: &[&str], acr: Option<&str>) -> Identity {
        Identity {
            issuer: "https://idp".into(),
            sub: sub.into(),
            groups: groups.iter().map(|s| s.to_string()).collect(),
            acr: acr.map(str::to_owned),
            email: None,
            iat: 0,
        }
    }

    fn ir() -> Policy {
        Policy {
            allow_groups: vec!["incident-response".into()],
            ..Default::default()
        }
    }

    const ART: ArtifactTimes = ArtifactTimes {
        created_at: 1000,
        expires_at: Some(2000),
    };

    #[test]
    fn default_deny_and_group_allow() {
        assert_eq!(
            evaluate(
                &ir(),
                &who("alice", &["incident-response"], None),
                ART,
                1500
            ),
            Ok(())
        );
        assert_eq!(
            evaluate(&ir(), &who("bob", &["staff"], None), ART, 1500),
            Err(Deny::NotInPolicy)
        );
        assert_eq!(
            evaluate(
                &Policy::default(),
                &who("alice", &["incident-response"], None),
                ART,
                1500
            ),
            Err(Deny::NotInPolicy)
        );
        let users = Policy {
            allow_users: vec!["bob".into()],
            ..Default::default()
        };
        assert_eq!(evaluate(&users, &who("bob", &[], None), ART, 1500), Ok(()));
        // Group names are matched exactly.
        assert_eq!(
            evaluate(
                &ir(),
                &who("eve", &["Incident-Response", "incident-response "], None),
                ART,
                1500
            ),
            Err(Deny::NotInPolicy)
        );
    }

    #[test]
    fn expiry_only_shortened() {
        let alice = who("alice", &["incident-response"], None);
        assert_eq!(evaluate(&ir(), &alice, ART, 2000), Err(Deny::Expired));
        let short = Policy {
            max_age_secs: Some(100),
            ..ir()
        };
        assert_eq!(evaluate(&short, &alice, ART, 1100), Ok(()));
        assert_eq!(evaluate(&short, &alice, ART, 1101), Err(Deny::Expired));
        let long = Policy {
            max_age_secs: Some(1_000_000),
            ..ir()
        };
        assert_eq!(evaluate(&long, &alice, ART, 2500), Err(Deny::Expired));
        let no_exp = ArtifactTimes {
            created_at: 1000,
            expires_at: None,
        };
        assert_eq!(evaluate(&ir(), &alice, no_exp, 1_000_000), Ok(()));
    }

    #[test]
    fn assurance_and_window() {
        let p = Policy {
            require_acr: vec!["phr".into()],
            not_before: Some(1200),
            not_after: Some(1800),
            ..ir()
        };
        assert_eq!(
            evaluate(&p, &who("alice", &["incident-response"], None), ART, 1500),
            Err(Deny::AssuranceTooLow)
        );
        assert_eq!(
            evaluate(
                &p,
                &who("alice", &["incident-response"], Some("pwd")),
                ART,
                1500
            ),
            Err(Deny::AssuranceTooLow)
        );
        let ok = who("alice", &["incident-response"], Some("phr"));
        assert_eq!(evaluate(&p, &ok, ART, 1500), Ok(()));
        assert_eq!(evaluate(&p, &ok, ART, 1100), Err(Deny::OutsideWindow));
        assert_eq!(evaluate(&p, &ok, ART, 1800), Err(Deny::OutsideWindow));
    }
}
