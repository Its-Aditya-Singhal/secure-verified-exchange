//! Narration and result bookkeeping for the demo.

use std::cell::RefCell;
use std::io::IsTerminal;

pub fn is_tty() -> bool {
    std::io::stdout().is_terminal()
}

pub struct Outcome {
    pub id: &'static str,
    pub title: &'static str,
    pub expected: &'static str,
    pub ok: bool,
    pub observed: String,
}

pub struct Ui {
    color: bool,
    quiet: bool,
    results: RefCell<Vec<Outcome>>,
}

impl Ui {
    pub fn new(color: bool, quiet: bool) -> Self {
        Ui {
            color,
            quiet,
            results: RefCell::new(Vec::new()),
        }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_owned()
        }
    }

    pub fn banner(&self, s: &str) {
        if !self.quiet {
            println!("{}", self.paint("1", s));
        }
    }

    pub fn scenario(&self, id: &str, title: &str) {
        if !self.quiet {
            println!();
            println!("{}", self.paint("1;36", &format!("[{id}] {title}")));
        }
    }

    /// A narration line (what the actor does or sees).
    pub fn say(&self, s: impl AsRef<str>) {
        if !self.quiet {
            println!("    {}", s.as_ref());
        }
    }

    /// Output from the system under test, dimmed.
    pub fn sys(&self, s: impl AsRef<str>) {
        if !self.quiet {
            println!("    {}", self.paint("2", &format!("│ {}", s.as_ref())));
        }
    }

    pub fn check(
        &self,
        id: &'static str,
        title: &'static str,
        expected: &'static str,
        ok: bool,
        observed: impl Into<String>,
    ) {
        let observed = observed.into();
        if !self.quiet {
            let mark = if ok {
                self.paint("32", "✔")
            } else {
                self.paint("1;31", "✘")
            };
            println!("  {mark} expected {expected}; observed {observed}");
        }
        self.results.borrow_mut().push(Outcome {
            id,
            title,
            expected,
            ok,
            observed,
        });
    }

    /// Print the summary table; true if every check passed.
    pub fn summary(&self) -> bool {
        let r = self.results.borrow();
        println!();
        println!("{}", self.paint("1", "Summary"));
        for o in r.iter() {
            let mark = if o.ok {
                self.paint("32", "✔")
            } else {
                self.paint("1;31", "✘")
            };
            println!("  {mark} {:<3} {:<52} {}", o.id, o.title, o.expected);
            if !o.ok {
                println!("        observed: {}", o.observed);
            }
        }
        let failed = r.iter().filter(|o| !o.ok).count();
        if failed == 0 {
            println!(
                "{}",
                self.paint(
                    "1;32",
                    &format!("All {} checks behaved as expected.", r.len())
                )
            );
        } else {
            println!(
                "{}",
                self.paint("1;31", &format!("{failed} of {} checks deviated.", r.len()))
            );
        }
        failed == 0 && !r.is_empty()
    }
}
