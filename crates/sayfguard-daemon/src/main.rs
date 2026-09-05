//! Sayfguard: lease-gated evidence sequestration and time-boxed retention.
//!
//! This binary is currently a scaffold. The architecture, retention policy,
//! and GDPR posture are specified in `docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md`
//! and `docs/ADR/`. Implementation lands module by module against that spec;
//! see each module's doc comment for what it owns and which ADR governs it.

mod lease;
mod notify;
mod retention;
mod sequester;
mod watcher;

fn main() {
    eprintln!("sayfguard: scaffold only, no runtime behavior yet");
    eprintln!("see docs/SAYFGUARD_TECHNICAL_DIRECTIVE.md before implementing");
    std::process::exit(1);
}
