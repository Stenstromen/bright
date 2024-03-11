use crate::types::{ DnsRecord, DnsRecords, CheckCAA };

use std::error::Error as stdError;
use std::prelude::v1::Result as stdResult;
use anyhow::{Result, Error};
use hickory_resolver::Resolver;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::error::ResolveError;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};

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

    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;

    let mut records: DnsRecords = DnsRecords { dns_records: Vec::new() };

    for record_type in &base_record_types {
        if *record_type == RecordType::SRV || *record_type == RecordType::TXT {
            continue;
        }

        check_and_add_record(&resolver, domain, *record_type, &mut records).unwrap();
    }

    let www_domain: String = format!("www.{}", domain);
    check_and_add_record(&resolver, &www_domain, RecordType::A, &mut records).unwrap();
    check_and_add_record(&resolver, &www_domain, RecordType::AAAA, &mut records).unwrap();

    for subdomain in srv_subdomains {
        let fqdn: String = format!("{}.{}", subdomain, domain);
        check_and_add_record(&resolver, &fqdn, RecordType::SRV, &mut records).unwrap();
    }

    for subdomain in txt_subdomains {
        let fqdn = format!("{}.{}", subdomain, domain);
        check_and_add_record(&resolver, &fqdn, RecordType::TXT, &mut records).unwrap();
    }

    Ok(records)
}

fn check_and_add_record(
    resolver: &Resolver,
    domain: &str,
    record_type: RecordType,
    records: &mut DnsRecords
) -> Result<(), Box<dyn stdError>> {
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

pub fn check_caa() -> Result<CheckCAA, Error> {
    Ok(CheckCAA {
        has_policy: true,
        has_policy_reporting: false,
    })
}