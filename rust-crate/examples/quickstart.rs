//! `cargo run --example quickstart`

use secretgenerator::{PassphraseOptions, PasswordOptions, entropy, passphrase, password};

fn main() -> Result<(), secretgenerator::Error> {
    let pw = password(
        PasswordOptions::default()
            .length(24)
            .charset("alphanum-symbols-v1")
            .require_classes("lower,upper,digit,symbol"),
    )?;
    println!("password:    {} ({:.1} bits)", pw.password, pw.entropy_bits);

    let phrase = passphrase(PassphraseOptions::default().words(8).separator("-"))?;
    println!("passphrase:  {}", phrase.password);

    let report = entropy("Tr0ub4dor&3")?;
    println!("Tr0ub4dor&3: {:.1} bits", report.entropy_bits);
    if let Some(ns) = report
        .crack_time_estimates
        .iter()
        .find(|e| e.profile_id == "nation-state-v1")
    {
        println!("crack:       {} (nation-state)", ns.human_readable);
    }
    Ok(())
}
