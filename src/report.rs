use std::fs::File;
use std::io::Write;
use chrono;

use crate::session_manager::Session;
use crate::args::Args;
use crate::file_operations;

pub fn print_result(session: Session) -> Session {
    println!();
    println!("\x1b[1m\x1b[40m-----------RESULT-----------\x1b[0m");
    println!("\x1b[1m\x1b[91mUNRESOLVED DOMAINS - {}\x1b[0m", session.get_unresolved_subdomains().len());
    for x in 0..session.get_unresolved_subdomains().len() {
        println!("{}", session.get_unresolved_subdomains()[x]);
    }
    println!("\x1b[1m\x1b[92mRESOLVED DOMAINS - {}\x1b[0m", session.get_resolved_subdomains().len());
    for x in 0..session.get_resolved_subdomains().len() {
        print!("{}", session.get_resolved_subdomains()[x]);
        println!(" - {}", session.get_resolved_ips()[x]);
    }
    println!("\x1b[1m\x1b[92mSUBDOMAINS WITH HTTP/S SERVICE - {}\x1b[0m", session.get_subdomains_http_https().len());
    if session.get_subdomains_http_https().len() == 0 {
        println!("No HTTP/S subdomain found, enable web service search by adding --loghttp")
    }
    for x in 0..session.get_subdomains_http_https().len() {
        println!("{}", session.get_subdomains_http_https()[x]);
    }
    println!();
    session
}

pub fn create_report(args: Args, session: Session)-> std::io::Result<()> {

    let mut report_file_path = args.get_report_folder_path().to_owned();
    report_file_path.push_str("/");
    report_file_path.push_str(&args.get_hostname());
    report_file_path.push_str("/");

    match file_operations::create_directory(&report_file_path) {
        Ok(()) => {},
        Err(_e) => {
            println!("Unable to create report");
            std::process::exit(1);
        },
    }
    let datetime: String = chrono::offset::Local::now().format("%Y%m%d-%H%M%S").to_string();
    report_file_path.push_str("result-");
    report_file_path.push_str(&datetime);
    report_file_path.push_str(".txt");

    let mut file = File::create(report_file_path).expect("Unable to create report");

    writeln!(file, "---UNRESOLVED DOMAINS--- ({})", session.get_unresolved_subdomains().len().to_string())?;
    for i in &session.get_unresolved_subdomains() {
        writeln!(file,"{}", i)?;
    }
    writeln!(file, "---RESOLVED DOMAINS--- ({})", session.get_resolved_subdomains().len().to_string())?;
    for i in &session.get_resolved_subdomains() {
        writeln!(file,"{}", i)?;
    }
    writeln!(file, "---SUBDOMAINS WITH HTTP/S SERVICE--- ({})", session.get_subdomains_http_https().len().to_string())?;
    for i in &session.get_subdomains_http_https() {                                                                                                                                                                  
        writeln!(file,"{}", i)?;                                                                                                                     
    }
    Ok(())
}

#[derive(serde::Serialize)]
struct ResolvedEntry {
    subdomain: String,
    ip: String,
}

#[derive(serde::Serialize)]
struct Counts {
    resolved: usize,
    unresolved: usize,
    http_services: usize,
}

#[derive(serde::Serialize)]
struct ReportJson {
    target: String,
    resolved: Vec<ResolvedEntry>,
    unresolved: Vec<String>,
    http_services: Vec<String>,
    counts: Counts,
}

fn build_report_json(target: &str, session: &Session) -> ReportJson {
    let subdomains = session.get_resolved_subdomains();
    let ips = session.get_resolved_ips();
    let resolved: Vec<ResolvedEntry> = subdomains
        .iter()
        .zip(ips.iter())
        .map(|(subdomain, ip)| ResolvedEntry {
            subdomain: subdomain.clone(),
            ip: ip.to_string(),
        })
        .collect();
    let unresolved = session.get_unresolved_subdomains();
    let http_services = session.get_subdomains_http_https();
    let counts = Counts {
        resolved: resolved.len(),
        unresolved: unresolved.len(),
        http_services: http_services.len(),
    };
    ReportJson {
        target: target.to_string(),
        resolved,
        unresolved,
        http_services,
        counts,
    }
}

/// Emit a single machine-readable JSON document to stdout.
pub fn print_result_json(target: &str, session: &Session) {
    let report = build_report_json(target, session);
    match serde_json::to_string(&report) {
        Ok(json) => println!("{}", json),
        Err(e) => eprintln!("Failed to serialize JSON output: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session_manager::Session;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn builds_paired_json() {
        let session = Session::load(
            vec![],
            vec!["www.example.com".to_string()],
            vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))],
            vec!["mail.example.com".to_string()],
            vec!["https://www.example.com".to_string()],
            "ua".to_string(),
        );
        let report = build_report_json("example.com", &session);
        let json = serde_json::to_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["target"], "example.com");
        assert_eq!(parsed["resolved"][0]["subdomain"], "www.example.com");
        assert_eq!(parsed["resolved"][0]["ip"], "93.184.216.34");
        assert_eq!(parsed["counts"]["resolved"], 1);
        assert_eq!(parsed["counts"]["unresolved"], 1);
        assert_eq!(parsed["counts"]["http_services"], 1);
    }
}

