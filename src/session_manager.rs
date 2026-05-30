
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::time::Instant;
use std::net::IpAddr;

use futures::StreamExt;
use trust_dns_resolver::AsyncResolver;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};

use crate::http_operations;
use crate::report;
use crate::args;

#[derive(Clone)]
pub struct Session {
    subdomains_found: Vec<String>,
    resolved_subdomains: Vec<String>,
    resolved_ips: Vec<IpAddr>,
    unresolved_subdomains: Vec<String>,
    subdomains_http_https: Vec<String>,
    useragent: String
}

impl Session {
    pub fn add_subdomains_found(&mut self, subdomain: String) {
        self.subdomains_found.push(subdomain);
    }
    pub fn get_subdomains_found(&self) -> Vec<String> {
        self.subdomains_found.clone()
    }
    pub fn set_subdomains_found(&mut self, subdomains_found: Vec<String>) {
        self.subdomains_found = subdomains_found;
    }

    pub fn get_resolved_subdomains(&self) -> Vec<String> {
        self.resolved_subdomains.clone()
    }
    pub fn add_resolved_subdomains(&mut self, subdomain: String) {
        self.resolved_subdomains.push(subdomain);
    }
    pub fn set_resolved_subdomains(&mut self, resolved_subdomains: Vec<String>) {
        self.resolved_subdomains = resolved_subdomains;
    }

    pub fn get_resolved_ips(&self) -> Vec<IpAddr> {
        self.resolved_ips.clone()
    }
    pub fn add_resolved_ips(&mut self, ip: IpAddr) {
        self.resolved_ips.push(ip);
    }
    pub fn set_resolved_ips(&mut self, resolved_ips: Vec<IpAddr>) {
        self.resolved_ips = resolved_ips;
    }

    pub fn get_unresolved_subdomains(&self) -> Vec<String> {
        self.unresolved_subdomains.clone()
    }
    pub fn add_unresolved_subdomains(&mut self, subdomain: String) {
        self.unresolved_subdomains.push(subdomain);
    }
    pub fn set_unresolved_subdomains(&mut self, unresolved_subdomains: Vec<String>) {
        self.unresolved_subdomains = unresolved_subdomains;
    }

    pub fn get_subdomains_http_https(&self) -> Vec<String> {
        self.subdomains_http_https.clone()
    }
    pub fn add_subdomains_http_https(&mut self, subdomain: String) {
        self.subdomains_http_https.push(subdomain);
    }
    pub fn set_subdomains_http_https(&mut self, subdomains_http_https: Vec<String>) {
        self.subdomains_http_https = subdomains_http_https;
    }

    pub fn set_useragent(&mut self, useragent: String) {
        self.useragent = useragent;
    }
    pub fn get_useragent(&self) -> String {
        self.useragent.clone()
    }

    pub fn init(useragent: String) -> Session {
        Session {
            subdomains_found: Vec::<String>::new(),
            resolved_subdomains: Vec::<String>::new(),
            resolved_ips: Vec::<IpAddr>::new(),
            unresolved_subdomains: Vec::<String>::new(),
            subdomains_http_https: Vec::<String>::new(),
            useragent: useragent,
        }
    }

    pub fn load(dns_subdomain_list: Vec<String>, resolved_subdomains: Vec<String>, resolved_ips: Vec<IpAddr>, unresolved_subdomains: Vec<String>, http_subdomain_list: Vec<String>, useragent: String) -> Session {
        Session {
            subdomains_found: dns_subdomain_list,
            resolved_subdomains: resolved_subdomains,
            resolved_ips: resolved_ips,
            unresolved_subdomains: unresolved_subdomains,
            subdomains_http_https: http_subdomain_list,
            useragent: useragent,
        }
    }
}

pub async fn start_session_operations() -> std::io::Result<()> {

    let start = Instant::now();

    let (session_args, useragentlist) = args::read_args();

    if session_args.get_hostname().is_empty() {
        eprintln!("\x1b[1m\x1b[91mError: no target domain specified. Use -d <domain> (see --help).\x1b[0m");
        return Ok(());
    }

    // In machine-readable mode, stdout must carry only the final JSON document,
    // so all progress/log output is suppressed (or routed to stderr elsewhere).
    let machine = session_args.is_machine_readable();

    let mut current_session: Session = Session::init(session_args.get_current_useragent());
    let nameserver = session_args.get_nameserver();
    current_session.add_subdomains_found(session_args.get_hostname());
    current_session.set_useragent(session_args.get_current_useragent());
    let verbose = session_args.get_verbose_mode();
    let random_agent_in_every_req = session_args.get_random_agent_in_every_req();
    let http_timeout = session_args.get_http_timeout();

    // Build a single shared resolver once and reuse it for every lookup.
    // Previously each lookup created its own tokio runtime + resolver, which
    // exhausted the open-file limit ("Too many open files") under the default
    // high thread count and aborted the whole process.
    let resolver = AsyncResolver::tokio(
        ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from_ips_clear(&[nameserver], 53)),
        ResolverOpts::default(),
    )
    .await
    .expect("failed to build DNS resolver");

    // Concurrent lookups are bounded by the configured thread number; they all
    // share the one resolver, so this no longer scales file descriptors with it.
    let concurrency = (session_args.get_dnsthread_number() as usize).max(1);

    //Start dns bruteforce
    if session_args.get_dnsbruteforce_mode() {
        if !machine { println!("\x1b[1m\x1b[40mDNS BRUTEFORCE\x1b[0m"); }

        let file = File::open(session_args.get_subdomain_txt_path())?;
        let reader = BufReader::new(file);
        let hostname = session_args.get_hostname();
        let names: Vec<String> = reader
            .lines()
            .filter_map(|line| line.ok())
            .map(|label| format!("{}.{}", label, hostname))
            .collect();

        let resolver_ref = &resolver;
        let found: Vec<String> = futures::stream::iter(names)
            .map(|name| async move {
                match resolver_ref.lookup_ip(name.clone()).await {
                    Ok(response) if response.iter().next().is_some() => {
                        if !machine {
                            println!("Found subdomain: {}\x1b[0m   \x1b[1m(DNS bruteforce)\x1b[0m", name);
                        }
                        Some(name)
                    }
                    _ => None,
                }
            })
            .buffer_unordered(concurrency)
            .filter_map(|item| async move { item })
            .collect()
            .await;

        for subdomain in found {
            current_session.add_subdomains_found(subdomain);
        }
        if !machine { println!(); }
    }
    //End dns bruteforce

    //Start internet search
    if session_args.get_searchengine_mode() {
        if !machine { println!("\x1b[1m\x1b[40mINTERNET SEARCH\x1b[0m"); }
        let subdomain_list_internet_search : Vec<String> = http_operations::search_internet(&session_args.get_hostname(), &current_session.get_useragent());

        for x in 0..subdomain_list_internet_search.len() {
            if !current_session.get_subdomains_found().contains(&subdomain_list_internet_search[x])
            {
                current_session.add_subdomains_found(subdomain_list_internet_search[x].clone());
                if !machine {
                    println!("Found subdomain: {}\x1b[0m   \x1b[1m(Internet search)\x1b[0m" , subdomain_list_internet_search[x]);
                }
            }
        }
        if !machine { println!(); }
    }
    // End internet search

    //Start HTTP content search
    if session_args.get_httpsearch_mode() {
        if !machine {
            println!("\x1b[1m\x1b[40mRECURSIVE HTTP CONTENT SEARCH\x1b[0m");
            println!("Sending requests...");
        }
        let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(session_args.get_httpthread_number().try_into().unwrap())
        .build()
        .unwrap();

        // Build one shared HTTP client and clone it (Arc-backed) into each
        // worker. Building a client per request across many threads previously
        // exhausted the open-file limit ("Too many open files").
        let http_client = http_operations::build_client(http_timeout);

        let (tx, rx) = std::sync::mpsc::channel();

        let current_subdomains : Vec<String> = current_session.get_subdomains_found();
        //First the function sends the http requests with threads, finds all subdomains available inside http content (previously discovered or not) then joins this discovered list of domains with current subdomain list makes sort and dedup to create the new unique subdomain list.
        for subdomain in current_subdomains.clone() {
            let tx = tx.clone();
            let mut thread_session = current_session.clone();
            let thread_useragentlist = useragentlist.clone();
            let client = http_client.clone();
            pool.spawn(move || {
                if random_agent_in_every_req {
                    thread_session.set_useragent(thread_useragentlist.get_random_useragent());
                }

                let (subdomain_list_http_content_search, _http_https_url) = http_operations::send_http_https_parse_response_with_client(&client, &subdomain, &thread_session.get_useragent(), verbose);
                let _ = tx.send(subdomain_list_http_content_search);
            });
        }
        drop(tx);
        let vec_vecsubs: Vec<Vec<String>> = rx.into_iter().collect();

        let mut new_subdomain_list : Vec<String> = current_subdomains.clone();
        for vector in vec_vecsubs {
            for subdomain in vector {
                new_subdomain_list.push(subdomain);
            }
        }
        new_subdomain_list.sort();
        new_subdomain_list.dedup();

        current_session.set_subdomains_found(new_subdomain_list.clone());

        let mut subdomain_difference_list: Vec<String> = new_subdomain_list.into_iter().filter(|item| !current_subdomains.contains(item)).collect();

        if !machine {
            for subdomain in subdomain_difference_list.clone() {
                println!("Found subdomain: {}\x1b[0m   \x1b[1m(HTTP content search)\x1b[0m" , subdomain);
            }
        }

        //After thread execution, function calculates the difference in subdomains before http content search and after. Function starts a recursive http content search on new found domains.
        let mut x_counter = 0;
        while x_counter < subdomain_difference_list.len() {

            if random_agent_in_every_req {
                current_session.set_useragent(useragentlist.get_random_useragent());
            }

            let (subdomain_list_http_content_search, _http_https_url) = http_operations::send_http_https_parse_response_with_client(&http_client, &subdomain_difference_list[x_counter], &current_session.get_useragent(), verbose);

            for y in 0..subdomain_list_http_content_search.len() {
                if !current_session.get_subdomains_found().contains(&subdomain_list_http_content_search[y])
                {
                    current_session.add_subdomains_found(subdomain_list_http_content_search[y].clone());
                    subdomain_difference_list.push(subdomain_list_http_content_search[y].clone());
                    if !machine {
                        println!("Found subdomain: {}\x1b[0m   \x1b[1m(HTTP content search)\x1b[0m" , subdomain_list_http_content_search[y]);
                    }
                }
            }
            x_counter += 1;
        }

        if !machine { println!(); }
    }
    //End HTTP content search

    //Print results
    let duration = start.elapsed();

    // Resolve every enumerated subdomain against the shared resolver. Each
    // (subdomain, ip) pair is kept together so the printed/reported pairing
    // is always correct regardless of completion order.
    if !machine { print!("Resolving found domains"); }
    let resolver_ref = &resolver;
    let pairs: Vec<(String, Option<IpAddr>)> = futures::stream::iter(current_session.get_subdomains_found())
        .map(|name| async move {
            match resolver_ref.lookup_ip(name.clone()).await {
                Ok(response) => (name, response.iter().next()),
                Err(_) => (name, None),
            }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;
    if !machine { println!(); }

    let mut resolved_subdomains: Vec<String> = Vec::new();
    let mut resolved_ips: Vec<IpAddr> = Vec::new();
    let mut unresolved_subdomains: Vec<String> = Vec::new();
    for (name, ip) in pairs {
        match ip {
            Some(ip) => {
                resolved_subdomains.push(name);
                resolved_ips.push(ip);
            }
            None => unresolved_subdomains.push(name),
        }
    }
    current_session.set_resolved_subdomains(resolved_subdomains);
    current_session.set_resolved_ips(resolved_ips);
    current_session.set_unresolved_subdomains(unresolved_subdomains);

    if session_args.get_log_http_https_domains() {
        let webservice_url_list : Vec<String> = http_operations::find_webservice_available_urls(current_session.get_resolved_subdomains(), &current_session.get_useragent(), session_args.get_httpthread_number());
        current_session.set_subdomains_http_https(webservice_url_list);
    }

    // Dispatch on output format: JSON document to stdout, or the human report.
    let current_session = if machine {
        report::print_result_json(&session_args.get_hostname(), &current_session);
        current_session
    } else {
        let printed = report::print_result(current_session);
        println!("\x1b[92mTime elapsed: {:?}\x1b[0m", duration);
        printed
    };

    if session_args.get_report_mode() {
        let _ = report::create_report(session_args, current_session);
    }

    Ok(())
}
