use crate::types::{
    CAARecords,
    CheckCAA,
    DnsRecord,
    DnsRecords,
    NSARecords,
    NSAddresses,
    NSRecord,
};

use std::error::Error as stdError;
use std::prelude::v1::Result as stdResult;
use anyhow::{ Result, Error };
use hickory_resolver::Resolver;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::error::ResolveError;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::config::{ NameServerConfig, Protocol, ResolverConfig, ResolverOpts };
use std::net::{ IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream };

pub fn dns_records(domain: &str) -> Result<DnsRecords> {
    let base_record_types: Vec<RecordType> = vec![
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::PTR,
        RecordType::SOA,
        RecordType::TXT,
        RecordType::CAA,
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::SSHFP
    ];

    let srv_subdomains: Vec<&str> = vec![
        "_sip._tls",
        "_sipfederationtls._tcp",
        "_xmpp-client._tcp",
        "_xmpp-server._tcp"
    ];

    let txt_subdomains = vec!["_dmarc", "_domainkey", "_mta-sts", "_smtp._tls"];

    let mut records: DnsRecords = DnsRecords { dns_records: Vec::new() };

    for record_type in &base_record_types {
        if *record_type == RecordType::SRV || *record_type == RecordType::TXT {
            continue;
        }

        check_and_add_record(domain, *record_type, &mut records).unwrap();
    }

    let www_domain: String = format!("www.{}", domain);
    check_and_add_record(&www_domain, RecordType::A, &mut records).unwrap();
    check_and_add_record(&www_domain, RecordType::AAAA, &mut records).unwrap();

    for subdomain in srv_subdomains {
        let fqdn: String = format!("{}.{}", subdomain, domain);
        check_and_add_record(&fqdn, RecordType::SRV, &mut records).unwrap();
    }

    for subdomain in txt_subdomains {
        let fqdn = format!("{}.{}", subdomain, domain);
        check_and_add_record(&fqdn, RecordType::TXT, &mut records).unwrap();
    }

    Ok(records)
}

fn check_and_add_record(
    domain: &str,
    record_type: RecordType,
    records: &mut DnsRecords
) -> Result<(), Box<dyn stdError>> {
    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;
    let result: stdResult<Lookup, ResolveError> = resolver.lookup(domain, record_type);
    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();

                let name: String = parts.get(0).unwrap_or(&"").to_string();
                let ttl: String = parts.get(1).unwrap_or(&"").to_string();
                let data: String = parts
                    .get(4..)
                    .unwrap_or(&[""])
                    .join(" ");

                records.dns_records.push(DnsRecord {
                    name,
                    ttl,
                    record_type: format!("{:?}", record_type),
                    data,
                });
            }
        }
        Err(_e) => {}
    }

    Ok(())
}

pub fn check_caa(domain: &str) -> Result<CheckCAA, Error> {
    let mut records: CheckCAA = CheckCAA {
        record_exists: false,
        reporting_enabled: false,
        records: Vec::new(),
    };

    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;
    let result: stdResult<Lookup, ResolveError> = resolver.lookup(domain, RecordType::CAA);

    if result.is_ok() {
        records.record_exists = true;
    }

    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();

                let name: &&str = parts.get(0).unwrap_or(&""); // domain name
                let mut issue_issuewild_iodef: String = parts.get(5).unwrap_or(&"").to_string(); // issue, issuewild, iodef

                if issue_issuewild_iodef == "" {
                    issue_issuewild_iodef = parts
                        .get(4)
                        .unwrap_or(&"")
                        .replace("/", "")
                        .replace("\"", "");
                }

                if issue_issuewild_iodef == "iodef" {
                    records.reporting_enabled = true;
                }

                let mut data: &&str = parts.get(6).unwrap_or(&""); // Allowed issuer domain name or iodef URL/Mailto

                if data == &"" {
                    data = parts.get(5).unwrap_or(&"");
                }

                records.records.push(CAARecords {
                    name: name.to_string(),
                    caa_type: issue_issuewild_iodef,
                    data: data.to_string(),
                });
            }
            Ok(records)
        }
        Err(_e) => Err(Error::msg("No CAA records found")),
    }
}

pub fn check_ns(domain: &str) -> Result<NSRecord, Error> {
    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;
    let result: stdResult<Lookup, ResolveError> = resolver.lookup(domain, RecordType::NS);
    let soa: stdResult<Lookup, ResolveError> = resolver.lookup(domain, RecordType::SOA);

    let mut ns_records: NSRecord = NSRecord {
        name: domain.to_string(),
        records: Vec::new(),
        nsaddresses: Vec::new(),
    };

    let mut soa_domain: String = "".to_string();

    match soa {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();
                let soadomain: String = parts.get(4).unwrap_or(&"").to_string();

                soa_domain = soadomain.clone();
            }
        }
        Err(_e) => {}
    }

    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();
                let nsdomain: String = parts.get(4).unwrap_or(&"").to_string();

                let data: String = parts
                    .get(4..)
                    .unwrap_or(&[""])
                    .join(" ");

                let mut referral_ns_soa: bool = false;
                let mut operational: bool = false;
                let mut ipv4available: bool = false;
                let mut ipv6available: bool = false;
                let mut ipv4_addresses: Vec<String> = Vec::new();
                let mut ipv6_addresses: Vec<String> = Vec::new();

                let mut nsa_addresses: Vec<NSAddresses> = Vec::new();

                if nsdomain == soa_domain {
                    referral_ns_soa = true;
                }

                let ipv4_result: stdResult<Lookup, ResolveError> = resolver.lookup(
                    &data,
                    RecordType::A
                );
                let ipv6_result: stdResult<Lookup, ResolveError> = resolver.lookup(
                    &data,
                    RecordType::AAAA
                );

                if ipv4_result.is_ok() || ipv6_result.is_ok() {
                    operational = true;
                }

                match ipv4_result {
                    Ok(lookup) => {
                        for record in lookup.record_iter() {
                            let record_str: String = record.to_string();
                            let parts: Vec<&str> = record_str.split_whitespace().collect();

                            let address: String = parts.get(4).unwrap_or(&"").to_string();

                            let ipv4address: String = address.to_string();

                            ipv4available = true;

                            ipv4_addresses.push(address.to_string());

                            let my_ip: IpAddr = IpAddr::V4(address.parse().unwrap());

                            let mut udp: bool = false;
                            let tcp: bool;
                            let mut operational: bool = false;
                            let authoritative: bool;
                            let recursive: bool;

                            match TcpStream::connect((my_ip, 53)) {
                                Ok(_) => {
                                    tcp = true;
                                }
                                Err(_e) => {
                                    tcp = false;
                                }
                            }

                            let name_server = NameServerConfig {
                                socket_addr: SocketAddr::new(my_ip, 53),
                                protocol: Protocol::Udp,
                                tls_dns_name: None,
                                bind_addr: None,
                                trust_negative_responses: true,
                            };

                            let mut config = ResolverConfig::new();
                            config.add_name_server(name_server);

                            let hickory_resolver = Resolver::new(config, ResolverOpts::default())?;

                            let result: stdResult<Lookup, ResolveError> = hickory_resolver.lookup(
                                domain,
                                RecordType::A
                            );

                            match result {
                                Ok(_lookup) => {
                                    authoritative = true;
                                    udp = true;
                                    operational = true;
                                }
                                Err(_e) => {
                                    authoritative = false;
                                }
                            }

                            let recursive_result: stdResult<
                                Lookup,
                                ResolveError
                            > = hickory_resolver.lookup("internetstiftelsen.se", RecordType::A);

                            match recursive_result {
                                Ok(_lookup) => {
                                    recursive = true;
                                }
                                Err(_e) => {
                                    recursive = false;
                                }
                            }

                            let mut in_addr_arpa: String = address
                                .split('.') // Split the string into an iterator based on the '.' delimiter
                                .rev() // Reverse the order of the elements in the iterator
                                .collect::<Vec<&str>>() // Collect the elements back into a vector
                                .join(".");

                            in_addr_arpa = format!("{}.in-addr.arpa", in_addr_arpa);

                            let mut ptr: String = "".to_string();

                            let ptr_lookup: stdResult<Lookup, ResolveError> = resolver.lookup(
                                &in_addr_arpa,
                                RecordType::PTR
                            );

                            match ptr_lookup {
                                Ok(lookup) => {
                                    for record in lookup.record_iter() {
                                        let record_str: String = record.to_string();
                                        let parts: Vec<&str> = record_str
                                            .split_whitespace()
                                            .collect();

                                        ptr = parts.get(4).unwrap_or(&"").to_string();
                                    }
                                }
                                Err(_e) => {}
                            }

                            let mut referral_ns_soa: bool = false;

                            if ptr == soa_domain {
                                referral_ns_soa = true;
                            }

                            nsa_addresses.push(NSAddresses {
                                ip: ipv4address,
                                ptr: ptr,
                                referral_ns_soa: referral_ns_soa,
                                operational: operational,
                                authoritative: authoritative,
                                recursive: recursive,
                                udp: udp,
                                tcp: tcp,
                            });
                        }
                    }
                    Err(_e) => {}
                }

                match ipv6_result {
                    Ok(lookup) => {
                        for record in lookup.record_iter() {
                            let record_str: String = record.to_string();
                            let parts: Vec<&str> = record_str.split_whitespace().collect();

                            let address: String = parts.get(4).unwrap_or(&"").to_string();

                            ipv6available = true;

                            let my_ip: IpAddr = IpAddr::V6(address.parse().unwrap());

                            let mut udp: bool = false;
                            let tcp: bool;
                            let mut operational: bool = false;
                            let authoritative: bool;
                            let recursive: bool;
                            let mut referral_ns_soa: bool = false;

                            match TcpStream::connect((my_ip, 53)) {
                                Ok(_) => {
                                    tcp = true;
                                }
                                Err(_e) => {
                                    tcp = false;
                                }
                            }

                            let name_server = NameServerConfig {
                                socket_addr: SocketAddr::new(my_ip, 53),
                                protocol: Protocol::Udp,
                                tls_dns_name: None,
                                bind_addr: None,
                                trust_negative_responses: true,
                            };

                            let mut config = ResolverConfig::new();
                            config.add_name_server(name_server);

                            let hickory_resolver = Resolver::new(config, ResolverOpts::default())?;

                            let result: stdResult<Lookup, ResolveError> = hickory_resolver.lookup(
                                domain,
                                RecordType::A
                            );

                            match result {
                                Ok(_lookup) => {
                                    authoritative = true;
                                    udp = true;
                                    operational = true;
                                }
                                Err(_e) => {
                                    authoritative = false;
                                }
                            }

                            let recursive_result: stdResult<
                                Lookup,
                                ResolveError
                            > = hickory_resolver.lookup("internetstiftelsen.se", RecordType::A);

                            match recursive_result {
                                Ok(_lookup) => {
                                    recursive = true;
                                }
                                Err(_e) => {
                                    recursive = false;
                                }
                            }

                            ipv6_addresses.push(address.to_string());

                            let ipv6address: String = address.to_string();

                            fn expand_ipv6_address(ipv6: &str) -> Result<String, &'static str> {
                                let parts: Vec<&str> = ipv6.split("::").collect();
                                if parts.len() > 2 {
                                    return Err("Invalid IPv6 address");
                                }

                                let hextets_before_double_colon: Vec<&str> = parts[0]
                                    .split(':')
                                    .collect::<Vec<&str>>();
                                let hextets_after_double_colon: Vec<&str> = if parts.len() == 2 {
                                    parts[1].split(':').collect::<Vec<&str>>()
                                } else {
                                    vec![]
                                };

                                let missing_hextets =
                                    8 -
                                    hextets_before_double_colon.len() -
                                    hextets_after_double_colon.len();
                                let zeros = vec!["0000"; missing_hextets];

                                let combined: Vec<&str> = [
                                    &hextets_before_double_colon[..],
                                    &zeros[..],
                                    &hextets_after_double_colon[..],
                                ].concat();

                                let expanded: Vec<String> = combined
                                    .into_iter()
                                    .map(|part| format!("{:0>4}", part))
                                    .collect();

                                Ok(expanded.join(":"))
                            }

                            fn ipv6_to_ptr(ipv6: &str) -> Result<String, &'static str> {
                                let expanded: String = expand_ipv6_address(ipv6)?;

                                let ptr: String = expanded
                                    .replace(":", "")
                                    .chars()
                                    .rev()
                                    .enumerate()
                                    .map(|(i, c)| (
                                        if i > 0 {
                                            format!(".{}", c)
                                        } else {
                                            c.to_string()
                                        }
                                    ))
                                    .collect::<String>();

                                Ok(format!("{}{}", ptr, ".ip6.arpa"))
                            }

                            let ipv6_arpa: stdResult<String, &str> = ipv6_to_ptr(&ipv6address);

                            let ptr_lookup: stdResult<Lookup, ResolveError> = resolver.lookup(
                                &ipv6_arpa.unwrap(),
                                RecordType::PTR
                            );

                            let ptr: String = ptr_lookup
                                .unwrap()
                                .record_iter()
                                .next()
                                .unwrap()
                                .to_string()
                                .split_whitespace()
                                .collect::<Vec<&str>>()
                                .get(4)
                                .unwrap_or(&"")
                                .to_string();

                            if ptr == soa_domain {
                                referral_ns_soa = true;
                            }

                            nsa_addresses.push(NSAddresses {
                                ip: ipv6address,
                                ptr: ptr,
                                referral_ns_soa: referral_ns_soa,
                                operational: operational,
                                authoritative: authoritative,
                                recursive: recursive,
                                udp: udp,
                                tcp: tcp,
                            });
                        }
                    }
                    Err(_e) => {}
                }

                ns_records.nsaddresses.append(&mut nsa_addresses);

                ns_records.records.push(NSARecords {
                    nsdomain,
                    operational: operational,
                    ipv4available: ipv4available,
                    ipv6available: ipv6available,
                    ipv4_adresses: ipv4_addresses,
                    ipv6_adresses: ipv6_addresses,
                    referral_ns_soa: referral_ns_soa,
                });
            }

            Ok(ns_records)
        }
        Err(_e) => Err(Error::msg("No NS records found")),
    }
}
