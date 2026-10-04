//! A check that the person at the computer is the account owner (Touch ID,
//! the computer's password or Windows Hello) before the app uses the keys.
//!
//! It is a software gate: it stops someone using an unlocked computer, not
//! malware running as the user (that would need hardware-bound keys, see the
//! threat model, T26). The [`Client`](crate::Client) enforces it, not the
//! UI:
//!
//! * [`Need::Session`] actions (send, open, change a file's rules, revoke)
//!   ask once, then not again until the gate has been idle for a while;
//! * [`Need::Always`] actions (approve someone, save a backup, change the
//!   password, sign out, change organization keys) ask every time.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{ClientError, Result};

/// How long an unlocked session lasts without use, by default.
pub const DEFAULT_IDLE: Duration = Duration::from_secs(15 * 60);
/// How long to wait for the person to answer the prompt.
pub const PROMPT_TIMEOUT: Duration = Duration::from_secs(120);

/// Asks the person to confirm. Implementations block until they answer.
pub trait UserPresence: Send + Sync {
    /// `Ok` if confirmed; [`ClientError::NotConfirmed`] otherwise.
    fn confirm(&self, reason: &str) -> Result<()>;
}

/// No check (tests, CLI and SDK by default).
pub struct AlwaysPresent;

impl UserPresence for AlwaysPresent {
    fn confirm(&self, _: &str) -> Result<()> {
        Ok(())
    }
}

/// Every prompt is refused (tests).
pub struct NeverPresent;

impl UserPresence for NeverPresent {
    fn confirm(&self, _: &str) -> Result<()> {
        Err(ClientError::NotConfirmed)
    }
}

/// What an action needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Need {
    /// An unlocked session (asks if locked or idle too long).
    Session,
    /// A fresh confirmation every time.
    Always,
}

/// The gate a [`Client`](crate::Client) consults.
pub struct PresenceGate {
    presence: Arc<dyn UserPresence>,
    idle: Mutex<Duration>,
    last_used: Mutex<Option<Instant>>,
    /// Number of prompts shown (for tests and the UI).
    prompts: Mutex<u64>,
}

impl PresenceGate {
    pub fn new(presence: Arc<dyn UserPresence>, idle: Duration) -> PresenceGate {
        PresenceGate {
            presence,
            idle: Mutex::new(idle),
            last_used: Mutex::new(None),
            prompts: Mutex::new(0),
        }
    }

    /// Lock now: the next session action asks again.
    pub fn lock(&self) {
        *self.last_used.lock().expect("presence lock") = None;
    }

    pub fn set_idle(&self, idle: Duration) {
        *self.idle.lock().expect("presence lock") = idle;
    }

    pub fn is_unlocked(&self) -> bool {
        let idle = *self.idle.lock().expect("presence lock");
        self.last_used
            .lock()
            .expect("presence lock")
            .is_some_and(|t| t.elapsed() < idle)
    }

    pub fn prompts(&self) -> u64 {
        *self.prompts.lock().expect("presence lock")
    }

    /// Check `need` for an action described by `reason` ("send a file").
    /// Blocks while the prompt is shown: call [`PresenceGate::require`]
    /// from async code.
    pub fn require_blocking(&self, need: Need, reason: &str) -> Result<()> {
        if need == Need::Session && self.is_unlocked() {
            *self.last_used.lock().expect("presence lock") = Some(Instant::now());
            return Ok(());
        }
        *self.prompts.lock().expect("presence lock") += 1;
        match self.presence.confirm(reason) {
            Ok(()) => {
                *self.last_used.lock().expect("presence lock") = Some(Instant::now());
                Ok(())
            }
            Err(e) => {
                self.lock();
                Err(e)
            }
        }
    }

    /// [`PresenceGate::require_blocking`] without blocking the async runtime.
    pub async fn require(self: &Arc<Self>, need: Need, reason: &str) -> Result<()> {
        if need == Need::Session && self.is_unlocked() {
            return self.require_blocking(need, reason);
        }
        let gate = self.clone();
        let reason = reason.to_owned();
        tokio::task::spawn_blocking(move || gate.require_blocking(need, &reason))
            .await
            .map_err(|e| ClientError::Other(e.to_string()))?
    }
}

/// The operating system's prompt: Touch ID or the login password on
/// macOS, Windows Hello (face, fingerprint or PIN) on Windows. Linux has no
/// prompt here (polkit needs an installed policy), so nothing is asked.
#[cfg(feature = "presence")]
pub struct SystemPresence;

#[cfg(feature = "presence")]
impl UserPresence for SystemPresence {
    fn confirm(&self, reason: &str) -> Result<()> {
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            use robius_authentication::{
                AndroidText, BiometricStrength, Context, PolicyBuilder, Text, WindowsText,
            };
            let policy = PolicyBuilder::new()
                .biometrics(Some(BiometricStrength::Strong))
                .password(true)
                .companion(true)
                .build()
                .ok_or_else(|| ClientError::Other("no way to confirm it's you".into()))?;
            // macOS shows "Secure Verified Exchange is trying to <reason>."
            let text = Text {
                android: AndroidText {
                    title: "Secure Verified Exchange",
                    subtitle: None,
                    description: None,
                },
                apple: reason,
                windows: WindowsText::new_truncated("Secure Verified Exchange", reason),
            };
            let (tx, rx) = std::sync::mpsc::channel();
            Context::new(())
                .authenticate(text, &policy, move |r| {
                    let _ = tx.send(r);
                })
                .map_err(|e| ClientError::Other(format!("can't ask to confirm it's you: {e:?}")))?;
            match rx.recv_timeout(PROMPT_TIMEOUT) {
                Ok(Ok(())) => Ok(()),
                _ => Err(ClientError::NotConfirmed),
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = reason;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counting(Mutex<Vec<String>>, bool);

    impl UserPresence for Counting {
        fn confirm(&self, reason: &str) -> Result<()> {
            self.0.lock().unwrap().push(reason.into());
            if self.1 {
                Ok(())
            } else {
                Err(ClientError::NotConfirmed)
            }
        }
    }

    #[test]
    fn sessions_ask_once_always_asks_every_time() {
        let p = Arc::new(Counting(Mutex::new(vec![]), true));
        let gate = PresenceGate::new(p.clone(), DEFAULT_IDLE);
        assert!(!gate.is_unlocked());
        gate.require_blocking(Need::Session, "send a file").unwrap();
        gate.require_blocking(Need::Session, "send a file").unwrap();
        assert_eq!(p.0.lock().unwrap().len(), 1);
        gate.require_blocking(Need::Always, "approve Bob").unwrap();
        gate.require_blocking(Need::Always, "approve Bob").unwrap();
        assert_eq!(p.0.lock().unwrap().len(), 3);
        gate.lock();
        gate.require_blocking(Need::Session, "open a file").unwrap();
        assert_eq!(p.0.lock().unwrap().len(), 4);
        assert_eq!(gate.prompts(), 4);
    }

    #[test]
    fn idle_sessions_lock_again() {
        let p = Arc::new(Counting(Mutex::new(vec![]), true));
        let gate = PresenceGate::new(p.clone(), Duration::from_millis(30));
        gate.require_blocking(Need::Session, "x").unwrap();
        std::thread::sleep(Duration::from_millis(60));
        assert!(!gate.is_unlocked());
        gate.require_blocking(Need::Session, "x").unwrap();
        assert_eq!(p.0.lock().unwrap().len(), 2);
    }

    #[test]
    fn a_refusal_locks() {
        let gate = PresenceGate::new(Arc::new(NeverPresent), DEFAULT_IDLE);
        assert!(matches!(
            gate.require_blocking(Need::Session, "x"),
            Err(ClientError::NotConfirmed)
        ));
        assert!(!gate.is_unlocked());
    }
}
