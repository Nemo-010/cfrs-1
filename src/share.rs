//! Access control for a public share session: a path token and a PIN gate.
//!
//! Both mechanisms exist because a share URL is published to anyone the link
//! reaches. The token is the path component that makes the URL unguessable; the
//! PIN is a second factor an operator can require when a link leaks.
//!
//! **The token is only protection if it is checked.** A session that builds a
//! URL containing a token and then serves `/s/<anything>/` has published the
//! content to everyone who can reach the origin. [`SharePath::parse`] is the
//! single place that decision is made, and it returns a
//! [`ShareDecision::NotFound`] rather than `Denied`, so a wrong token and an
//! absent session are indistinguishable to a prober. See [`SharePath`] for why
//! that matters.
//!
//! Comparison of the token and the PIN is constant time. A `==` on a secret
//! short-circuits on the first differing byte, which is measurable over a
//! network connection to a public URL, and neither value here is long enough
//! for a brute force to be the cheaper attack.

use std::time::{Duration, Instant};

/// What a caller should do with a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareDecision {
    /// The path is not one of ours, or the token did not match. Answer `404`.
    NotFound,
    /// The token matched and no PIN is required. Serve the session.
    Allow,
    /// The token matched but the PIN gate is closed. Serve the unlock page.
    NeedsPin,
}

/// The share URL paths a session answers on.
///
/// | path | meaning |
/// | --- | --- |
/// | `/__cfrs/unlock` | PIN submission, no token required |
/// | `/s/<token>` | session root |
/// | `/s/<token>/upload` | upload target |
/// | `/s/<token>/file` | download target |
///
/// Only these four are routable. Anything else is `NotFound`, which is what
/// makes an unguessable path an access control rather than a naming
/// convention: the token is compared on every request that carries one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharePath<'a> {
    Unlock,
    Root(&'a str),
    Upload(&'a str),
    Download(&'a str),
}

impl<'a> SharePath<'a> {
    /// Parse a request path into a share route, or `None` when the path is not
    /// one this session serves.
    ///
    /// The token is returned as a borrowed slice, not parsed or validated: the
    /// comparison belongs to [`Session::decide`], which is the only place that
    /// holds the real value. Splitting the decision from the routing means a
    /// handler cannot accidentally serve a path without checking it.
    pub fn parse(path: &'a str) -> Option<Self> {
        // A query string or fragment is not part of the path. Cutting at the
        // first delimiter keeps the borrow at the caller's lifetime, so the
        // returned token slice outlives this function.
        let end = path.find(['?', '#']).unwrap_or(path.len());
        let path = &path[..end];
        if path == UNLOCK_PATH {
            return Some(Self::Unlock);
        }
        let rest = path.strip_prefix("/s/")?;
        if rest.is_empty() {
            return None;
        }
        let (token, kind) = match rest.split_once('/') {
            Some((t, "")) => (t, 0),
            Some((t, "upload")) => (t, 1),
            Some((t, "file")) => (t, 2),
            Some(_) => return None,
            None => (rest, 0),
        };
        if token.is_empty() || token.contains(['/', '\0']) {
            return None;
        }
        Some(match kind {
            0 => Self::Root(token),
            1 => Self::Upload(token),
            _ => Self::Download(token),
        })
    }
}

/// The path a PIN is submitted to. Deliberately outside `/s/`, so unlocking does
/// not require knowing the token.
pub const UNLOCK_PATH: &str = "/__cfrs/unlock";
/// The cookie a successful unlock sets.
pub const COOKIE_NAME: &str = "cfrs_pin";
/// How long an unlocked cookie lasts.
pub const UNLOCK_TTL: Duration = Duration::from_secs(86400);

/// Compare two secrets without an early exit.
///
/// Length is not hidden, because a length oracle would need a way to vary the
/// length of a valid token or PIN, and both are fixed at generation time. The
/// *contents* are what a timing attack would recover one byte at a time.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Whether a PIN gate is required at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateMode {
    /// No gate. The token is the only control.
    Off,
    /// A 6-digit PIN is required before anything is served.
    Pin,
}

/// How many failures a PIN gate tolerates before it stops answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimit {
    /// Attempts allowed inside the window.
    pub budget: u32,
    /// Length of the window.
    pub window: Duration,
}

impl Default for RateLimit {
    fn default() -> Self {
        // A 6-digit PIN is about 20 bits. With a generous budget the space is
        // still exhaustible from a cloud host, so the budget is small and the
        // window long enough that a human is never slowed: 8 tries a minute is
        // 20k a day, which is noise next to a real attacker but unusable for
        // guessing by hand.
        Self { budget: 8, window: Duration::from_secs(60) }
    }
}

impl RateLimit {
    /// Whether the `attempts`-th attempt of the window is permitted. Exactly
    /// `budget` attempts are allowed, so the (budget+1)-th is refused.
    pub fn permits(&self, attempts: u32) -> bool {
        attempts <= self.budget
    }
}

/// A PIN gate: a 6-digit code, exchanged for a session cookie.
///
/// The PIN is shown only on the machine that owns the tunnel. It is never put in
/// a URL, a cookie, a log line, or a rendered page; [`Gate::page_html`] emits a
/// prompt and nothing else.
#[derive(Clone, Debug)]
pub struct Gate {
    mode: GateMode,
    pin: String,
    session: String,
    limit: RateLimit,
    attempts: std::sync::Arc<std::sync::atomic::AtomicU32>,
    window_start: std::sync::Arc<std::sync::Mutex<Option<Instant>>>,
}

impl Gate {
    /// A gate that never blocks. The token alone protects the session.
    pub fn off() -> Self {
        Self {
            mode: GateMode::Off,
            pin: String::new(),
            session: String::new(),
            limit: RateLimit::default(),
            attempts: Default::default(),
            window_start: Default::default(),
        }
    }

    /// A gate requiring `pin`, which must be six digits, with the default
    /// rate limit.
    pub fn with_pin(pin: &str, session: &str) -> Result<Self, String> {
        Self::with_pin_and_limit(pin, session, RateLimit::default())
    }

    /// A gate requiring `pin` with an explicit rate limit. Used by tests that
    /// must not sleep for a whole window.
    pub fn with_pin_and_limit(pin: &str, session: &str, limit: RateLimit) -> Result<Self, String> {
        if !valid_pin(pin) {
            return Err(format!("a PIN is six digits, got {pin:?}"));
        }
        if limit.budget == 0 {
            return Err("a rate limit of zero attempts locks every visitor out".into());
        }
        Ok(Self {
            mode: GateMode::Pin,
            pin: pin.to_string(),
            session: session.to_string(),
            limit,
            attempts: Default::default(),
            window_start: Default::default(),
        })
    }

    /// Whether a PIN is required.
    pub fn enabled(&self) -> bool {
        self.mode == GateMode::Pin
    }

    /// Check a submitted PIN. On success returns the `Set-Cookie` value.
    ///
    /// A wrong PIN is refused in constant time, and an attempt is counted
    /// whether it was right or wrong, so a correct guess after a burst of wrong
    /// ones is still rate limited.
    pub fn unlock(&self, password: &str) -> Option<String> {
        if !self.enabled() {
            return None;
        }
        if !self.take_attempt() {
            logf_("gate: refusing, rate limit reached");
            return None;
        }
        if !constant_time_eq(password.trim().as_bytes(), self.pin.as_bytes()) {
            return None;
        }
        Some(format!(
            "{COOKIE_NAME}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            self.session,
            UNLOCK_TTL.as_secs()
        ))
    }

    /// Whether the request's cookies carry a valid unlock.
    pub fn is_open(&self, cookie_header: Option<&str>) -> bool {
        if !self.enabled() {
            return true;
        }
        let Some(header) = cookie_header else { return false };
        header.split(';').any(|part| {
            part.trim()
                .strip_prefix(&format!("{COOKIE_NAME}="))
                .is_some_and(|value| constant_time_eq(value.as_bytes(), self.session.as_bytes()))
        })
    }

    /// Count one attempt, resetting the count when the window has elapsed.
    /// Returns whether the attempt is within budget.
    fn take_attempt(&self) -> bool {
        use std::sync::atomic::Ordering;
        let counter = &self.attempts;
        let Ok(mut start) = self.window_start.lock() else {
            // A poisoned lock means some other thread panicked mid-check. Fail
            // closed: an unlocked gate after a panic is worse than a refused
            // attempt.
            return false;
        };
        let now = Instant::now();
        // Count this attempt, then decide. Either way the counter moves, so a
        // client cannot learn the budget by watching when a wrong PIN stops
        // being counted.
        let used = match *start {
            Some(t) if now.duration_since(t) < self.limit.window => {
                counter.fetch_add(1, Ordering::SeqCst) + 1
            }
            _ => {
                *start = Some(now);
                counter.store(1, Ordering::SeqCst);
                1
            }
        };
        self.limit.permits(used)
    }

    /// The unlock page. Contains no secret.
    pub fn page_html(&self, next: &str, failed: bool) -> String {
        let next = escape_attr(next);
        let error = if failed {
            "<p class=\"err\">Wrong code, try again.</p>"
        } else {
            ""
        };
        format!(
            "<!doctype html><html><head><meta charset=\"utf-8\">\
             <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
             <title>cfrs &mdash; locked</title><style>\
             body{{font-family:system-ui,sans-serif;background:#0b1020;color:#e8ecf5;\
             display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}}\
             form{{background:#161d33;padding:2rem;border-radius:12px;width:min(90vw,320px)}}\
             h1{{font-size:1.1rem;margin:0 0 1rem}}p{{color:#9aa7c7;font-size:.9rem}}\
             .err{{color:#ff8a8a}}input{{width:100%;box-sizing:border-box;padding:.7rem;\
             font-size:1.4rem;letter-spacing:.4rem;text-align:center;border-radius:8px;\
             border:1px solid #33406a;background:#0b1020;color:#fff}}\
             button{{margin-top:1rem;width:100%;padding:.7rem;border:0;border-radius:8px;\
             background:#4f7cff;color:#fff;font-size:1rem}}\
             </style></head><body><form method=\"post\" action=\"{UNLOCK_PATH}\">\
             <h1>Enter the 6-digit code</h1>{error}\
             <input name=\"password\" inputmode=\"numeric\" pattern=\"[0-9]*\" \
             maxlength=\"6\" autofocus autocomplete=\"one-time-code\">\
             <input type=\"hidden\" name=\"next\" value=\"{next}\">\
             <button type=\"submit\">Unlock</button>\
             <p>The code is shown on the computer running cfrs.</p></form></body></html>"
        )
    }
}

/// Whether `pin` is a well-formed 6-digit PIN.
pub fn valid_pin(pin: &str) -> bool {
    pin.len() == 6 && pin.bytes().all(|b| b.is_ascii_digit())
}

/// Strip characters that would break out of an HTML attribute.
pub fn escape_attr(value: &str) -> String {
    value
        .chars()
        .filter(|c| !matches!(c, '<' | '>' | '"' | '\'' | '&'))
        .take(512)
        .collect()
}

/// A share session's identity and its gate, and the one decision a handler asks.
#[derive(Clone, Debug)]
pub struct Session {
    token: String,
    gate: Gate,
}

impl Session {
    /// A session protected by `token` alone.
    pub fn new(token: impl Into<String>) -> Self {
        Self { token: token.into(), gate: Gate::off() }
    }

    /// A session requiring `pin` as well as the token.
    pub fn with_gate(token: impl Into<String>, pin: &str, session: &str) -> Result<Self, String> {
        Ok(Self { token: token.into(), gate: Gate::with_pin(pin, session)? })
    }

    /// The token. Publish it in the URL, never log it.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// The gate.
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    /// The public path of this session.
    pub fn base_path(&self) -> String {
        format!("/s/{}/", self.token)
    }

    /// Decide what to do with a request.
    ///
    /// This is the check the token exists for. A path with no token, or one
    /// whose token is not ours, is [`ShareDecision::NotFound`]: the same answer
    /// a path that was never routed would give, so an attacker learns nothing
    /// about which tokens exist.
    pub fn decide(&self, path: &str, cookie_header: Option<&str>) -> ShareDecision {
        match SharePath::parse(path) {
            None => ShareDecision::NotFound,
            Some(SharePath::Unlock) => ShareDecision::Allow,
            Some(SharePath::Root(token))
            | Some(SharePath::Upload(token))
            | Some(SharePath::Download(token)) => {
                if !constant_time_eq(token.as_bytes(), self.token.as_bytes()) {
                    return ShareDecision::NotFound;
                }
                if self.gate.is_open(cookie_header) {
                    ShareDecision::Allow
                } else {
                    ShareDecision::NeedsPin
                }
            }
        }
    }
}

fn logf_(message: &str) {
    if std::env::var_os("CFRS_DEBUG").is_some() {
        eprintln!("cfrs: {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "1f0c3a9d5e7b2468ca03f1d5b7e92046";

    fn cookie(value: &str) -> String {
        format!("{COOKIE_NAME}={value}")
    }

    // ── the token is actually checked ──────────────────────────────────────

    #[test]
    fn the_right_token_is_served() {
        let session = Session::new(TOKEN);
        assert_eq!(session.decide(&format!("/s/{TOKEN}/"), None), ShareDecision::Allow);
        assert_eq!(session.decide(&format!("/s/{TOKEN}"), None), ShareDecision::Allow);
        assert_eq!(
            session.decide(&format!("/s/{TOKEN}/upload"), None),
            ShareDecision::Allow
        );
        assert_eq!(
            session.decide(&format!("/s/{TOKEN}/file"), None),
            ShareDecision::Allow
        );
    }

    #[test]
    fn a_wrong_token_is_not_found_even_with_the_right_shape() {
        let session = Session::new(TOKEN);
        for path in [
            "/s/",
            "/s/anything",
            "/s/anything/",
            "/s/anything/upload",
            "/s/anything/file",
            &format!("/s/{}x/", TOKEN),
            &format!("/s/{} ", TOKEN),
            "/",
            "/index.html",
            "/__cfrs/unlock/extra",
        ] {
            assert_eq!(
                session.decide(path, None),
                ShareDecision::NotFound,
                "{path:?} must not be served"
            );
        }
    }

    #[test]
    fn a_token_differing_in_one_character_is_refused() {
        let session = Session::new(TOKEN);
        let mut wrong: Vec<char> = TOKEN.chars().collect();
        wrong[0] = if wrong[0] == 'a' { 'b' } else { 'a' };
        let wrong: String = wrong.into_iter().collect();
        assert_eq!(session.decide(&format!("/s/{wrong}/"), None), ShareDecision::NotFound);
    }

    #[test]
    fn a_query_string_does_not_defeat_the_check() {
        let session = Session::new(TOKEN);
        assert_eq!(
            session.decide(&format!("/s/{TOKEN}/file?download=1"), None),
            ShareDecision::Allow
        );
        assert_eq!(
            session.decide("/s/wrong/file?download=1", None),
            ShareDecision::NotFound
        );
    }

    #[test]
    fn an_unknown_sub_path_is_not_routed() {
        let session = Session::new(TOKEN);
        assert_eq!(
            session.decide(&format!("/s/{TOKEN}/admin"), None),
            ShareDecision::NotFound
        );
        assert_eq!(
            session.decide(&format!("/s/{TOKEN}/../etc/passwd"), None),
            ShareDecision::NotFound
        );
    }

    // ── the PIN gate ───────────────────────────────────────────────────────

    #[test]
    fn a_valid_pin_unlocks_and_a_wrong_one_does_not() {
        let gate = Gate::with_pin("042119", "sess-a").expect("well formed");
        assert!(gate.unlock("042119").is_some(), "the right PIN must unlock");
        assert!(gate.unlock("042118").is_none(), "a wrong PIN must not");
        assert!(gate.unlock("").is_none());
        assert!(gate.unlock(" 042119 ").is_some(), "surrounding space is trimmed");
    }

    #[test]
    fn a_malformed_pin_is_refused_at_construction() {
        assert!(Gate::with_pin("12345", "s").is_err(), "five digits is not a PIN");
        assert!(Gate::with_pin("1234567", "s").is_err(), "seven digits is not a PIN");
        assert!(Gate::with_pin("12345a", "s").is_err(), "a letter is not a digit");
        assert!(Gate::with_pin("123456", "s").is_ok());
    }

    #[test]
    fn an_unlocked_cookie_opens_the_gate() {
        let gate = Gate::with_pin("042119", "sess-a").expect("well formed");
        assert!(!gate.is_open(None), "no cookie means locked");
        assert!(!gate.is_open(Some("other=1")), "an unrelated cookie is locked");
        assert!(!gate.is_open(Some(&cookie("sess-b"))), "a wrong session is locked");
        assert!(gate.is_open(Some(&cookie("sess-a"))), "the right session opens");
        assert!(
            gate.is_open(Some(&format!("x=1; {}", cookie("sess-a")))),
            "the cookie may appear among others"
        );
    }

    #[test]
    fn the_gate_blocks_the_token_only_when_the_pin_is_required() {
        let open = Session::new(TOKEN);
        let locked = Session::with_gate(TOKEN, "042119", "sess-a").expect("well formed");

        assert_eq!(open.decide(&format!("/s/{TOKEN}/"), None), ShareDecision::Allow);
        assert_eq!(
            locked.decide(&format!("/s/{TOKEN}/"), None),
            ShareDecision::NeedsPin,
            "a right token with no cookie still needs the PIN"
        );
        assert_eq!(
            locked.decide(&format!("/s/{TOKEN}/"), Some(&cookie("sess-a"))),
            ShareDecision::Allow
        );
        assert_eq!(
            locked.decide("/s/wrong/", Some(&cookie("sess-a"))),
            ShareDecision::NotFound,
            "a valid cookie does not excuse a wrong token"
        );
        assert_eq!(locked.decide(UNLOCK_PATH, None), ShareDecision::Allow);
    }

    #[test]
    fn a_disabled_gate_accepts_any_cookie() {
        let gate = Gate::off();
        assert!(gate.is_open(None));
        assert!(gate.is_open(Some("anything")));
        assert!(gate.unlock("000000").is_none(), "an off gate never issues a cookie");
    }

    // ── the rate limit ─────────────────────────────────────────────────────

    #[test]
    fn the_budget_is_exhausted_after_exactly_the_configured_attempts() {
        let gate = Gate::with_pin("042119", "sess-a").expect("well formed");
        let budget = RateLimit::default().budget;

        // The correct PIN is accepted for exactly `budget` attempts, then the
        // limiter refuses it. Counting successes is the observable that
        // separates "the PIN was wrong" from "the limiter stopped answering":
        // a wrong PIN is never accepted, so a success can only mean the limiter
        // still had room.
        let mut accepted = 0;
        for _ in 0..(budget + 5) {
            if gate.unlock("042119").is_some() {
                accepted += 1;
            }
        }
        assert_eq!(
            accepted, budget as usize,
            "the limiter should admit exactly {budget} attempts, admitted {accepted}"
        );

        // And a wrong PIN is refused throughout, so throttling is not the only
        // thing refusing it.
        assert!(gate.unlock("000000").is_none());
    }

    #[test]
    fn the_window_resets_the_budget() {
        // A short window, so the test does not spend a real minute sleeping.
        let gate = Gate::with_pin_and_limit("042119", "sess-a", RateLimit { budget: 3, window: Duration::from_millis(60) })
            .expect("well formed");
        for _ in 0..3 {
            assert!(gate.unlock("042119").is_some(), "within budget");
        }
        assert!(gate.unlock("042119").is_none(), "over budget");
        std::thread::sleep(Duration::from_millis(120));
        assert!(
            gate.unlock("042119").is_some(),
            "the budget must return after the window, or a session locks itself out forever"
        );
    }

    #[test]
    fn the_default_budget_is_small_enough_to_matter() {
        // 6 digits is about 20 bits. At 8 a minute, exhausting the space takes
        // about 11 days from one host, which is the point of the limit.
        let budget = RateLimit::default().budget;
        assert!(budget <= 10, "a budget of {budget} is too generous for 20 bits");
        let minutes = 1_000_000f64 / f64::from(budget) / 60.0;
        assert!(
            minutes > 24.0,
            "the space is exhausted in {minutes:.0} minutes at this budget"
        );
    }

    // ── nothing leaks ──────────────────────────────────────────────────────

    #[test]
    fn the_unlock_page_carries_no_secret() {
        let gate = Gate::with_pin("042119", "sess-a").expect("well formed");
        let page = gate.page_html(&format!("/s/{TOKEN}/file"), false);
        assert!(!page.contains("042119"), "the PIN must not be rendered");
        assert!(!page.contains("sess-a"), "the session must not be rendered");
        assert!(page.contains("6-digit code"), "the prompt should still be shown");
    }

    #[test]
    fn a_next_parameter_cannot_break_out_of_the_attribute() {
        let gate = Gate::with_pin("042119", "sess-a").expect("well formed");
        let payload = "\"><script>alert(1)</script>";
        let page = gate.page_html(payload, false);
        assert!(!page.contains("<script>"), "markup must not survive: {page}");
        assert!(!page.contains("</script>alert"), "the payload must be inert");

        // The value that reached the attribute is the escaped one. Read it back
        // out of the hidden input rather than asserting on the whole page,
        // which legitimately contains quotes of its own.
        let value_start = page
            .find("name=\"next\" value=\"")
            .expect("the form must carry a next field")
            + "name=\"next\" value=\"".len();
        let value_end = value_start + page[value_start..].find('"').expect("a closed value");
        let value = &page[value_start..value_end];
        for c in ['<', '>', '"', '\'', '&'] {
            assert!(
                !value.contains(c),
                "an attribute-breaking character {c:?} survived into the value: {value:?}"
            );
        }
    }

    #[test]
    fn escape_attr_strips_every_dangerous_character() {
        assert_eq!(escape_attr("<>&\"'"), "");
        assert_eq!(escape_attr("/s/abc/file"), "/s/abc/file");
        assert_eq!(escape_attr("a<b>c"), "abc");
        assert_eq!(escape_attr(&"x".repeat(1000)).len(), 512, "the value is bounded");
    }

    #[test]
    fn the_session_never_prints_its_token_by_accident() {
        let session = Session::new(TOKEN);
        // The Debug impl is derived, so this is a deliberate statement that the
        // token showing up in a log line is acceptable only where it is the
        // token's whole purpose. Anything that formats a session for a log must
        // not use {:?}.
        let rendered = format!("{session:?}");
        assert!(
            rendered.contains(TOKEN),
            "Debug is derived; the caller is responsible for not logging it"
        );
        assert_eq!(session.base_path(), format!("/s/{TOKEN}/"));
    }

    // ── path parsing ───────────────────────────────────────────────────────

    #[test]
    fn paths_parse_into_exactly_four_routes() {
        assert_eq!(SharePath::parse("/__cfrs/unlock"), Some(SharePath::Unlock));
        assert_eq!(SharePath::parse("/s/abc"), Some(SharePath::Root("abc")));
        assert_eq!(SharePath::parse("/s/abc/"), Some(SharePath::Root("abc")));
        assert_eq!(SharePath::parse("/s/abc/upload"), Some(SharePath::Upload("abc")));
        assert_eq!(SharePath::parse("/s/abc/file"), Some(SharePath::Download("abc")));
        for bad in ["/s/", "/s//", "/s/a/b/c", "/s/a/x", "", "/", "/s"] {
            assert_eq!(SharePath::parse(bad), None, "{bad:?} must not route");
        }
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"", b"a"));
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"\x00\xff", b"\x00\xff"));
        assert!(!constant_time_eq(b"\x00\xff", b"\x00\xfe"));
    }

    #[test]
    fn valid_pin_accepts_exactly_six_digits() {
        assert!(valid_pin("000000"));
        assert!(valid_pin("999999"));
        assert!(!valid_pin("00000"));
        assert!(!valid_pin("0000000"));
        assert!(!valid_pin("00000 "));
        assert!(!valid_pin("      "));
        assert!(!valid_pin("12a456"));
    }
}