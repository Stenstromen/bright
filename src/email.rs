use crate::types::{ Email, Mx };

use std::prelude::v1::Result as stdResult;

use anyhow::{ Result, Error };

use hickory_resolver::Resolver;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::error::ResolveError;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::config::{ NameServerConfig, Protocol, ResolverConfig, ResolverOpts };
use trust_dns_resolver::lookup::Lookup as TDRLookup;
use trust_dns_resolver::error::ResolveError as TDRResolveError;
use trust_dns_resolver::proto::rr::RecordType as TDRRecordType;
use trust_dns_resolver::Resolver as TDRResolver;
use trust_dns_resolver::config::{
    ResolverConfig as TDRResolverConfig,
    ResolverOpts as TDRResolverOpts,
};

fn check_record(domain: &str, record_type: RecordType) -> Result<String> {
    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;
    let result: stdResult<Lookup, ResolveError> = resolver.lookup(domain, record_type);

    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                return Ok(record_str.split_whitespace().last().unwrap_or(&"").to_string());
            }
        }
        Err(e) => {
            let error = Error::new(e);
            return Err(error);
        }
    }

    Ok("".to_string())
}

fn check_dnssec(domain: &str) -> Result<bool> {
    let mut opts: TDRResolverOpts = TDRResolverOpts::default();
    opts.validate = true;

    let resolver: TDRResolver = TDRResolver::new(TDRResolverConfig::quad9(), opts).unwrap();

    let result: stdResult<TDRLookup, TDRResolveError> = resolver.lookup(
        domain,
        TDRRecordType::DNSKEY
    );

    match result {
        Ok(_lookup) => {
            return Ok(true);
        }

        Err(_e) => {
            return Ok(false);
        }
    }
}

pub fn check_email(domain: &str) -> Result<Email> {
    let resolver: Resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;
    let result: stdResult<Lookup, ResolveError> = resolver.lookup(domain, RecordType::MX);

    let mut mx_records: Vec<Mx> = Vec::new();

    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str: String = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();
                let preference_string = parts.get(4).unwrap_or(&"0");
                let preference: i8 = preference_string.parse().unwrap_or(0);
                let name: String = parts.get(5).unwrap_or(&"").to_string();
                let ipv4 = check_record(&name, RecordType::A).unwrap_or("".to_string());
                let ipv6 = check_record(&name, RecordType::AAAA).unwrap_or("".to_string());

                let mut in_addr_arpa: String = ipv4
                    .split('.')
                    .rev()
                    .collect::<Vec<&str>>()
                    .join(".");

                in_addr_arpa = format!("{}.in-addr.arpa", in_addr_arpa);

                let ptr = check_record(&in_addr_arpa, RecordType::PTR).unwrap_or("".to_string());
                let dnssec = check_dnssec(&name).unwrap_or(false);

                let mx_record = Mx {
                    name: name,
                    ipv4: ipv4,
                    ipv6: ipv6,
                    ptr: ptr,
                    preference: preference,
                    dnssec: dnssec,
                };

                mx_records.push(mx_record);
            }
        }
        Err(e) => {
            let error = Error::new(e);
            return Err(error);
        }
    }

    let email = Email {
        mx: mx_records,
    };

    Ok(email)
}
