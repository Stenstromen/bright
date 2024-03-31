use std::sync::Arc;
use async_graphql::{ SimpleObject, Schema, EmptyMutation, EmptySubscription };

#[doc = "Check DNS Records for a domain"]
#[derive(SimpleObject)]
pub struct DnsRecord {
    pub name: String,
    pub ttl: String,
    pub record_type: String,
    pub data: String,
}

#[derive(SimpleObject)]
pub struct DnsRecords {
    pub dns_records: Vec<DnsRecord>,
}

#[doc = "CAA Records for a domain"]
#[derive(SimpleObject)]
pub struct CAARecords {
    pub name: String,
    pub caa_type: String,
    pub data: String,
}

#[doc = "Check if CAA Records exist and if reporting is enabled for a domain"]
#[derive(SimpleObject)]
pub struct CheckCAA {
    pub record_exists: bool,
    pub reporting_enabled: bool,
    pub records: Vec<CAARecords>,
}
#[derive(Default)]
pub struct DomainCheck {
    pub domain: Arc<String>,
}

#[doc = "Check Nameserver Records for a domain"]
#[derive(SimpleObject)]
pub struct NSARecords {
    pub nsdomain: String,
    pub operational: bool,
    pub ipv4available: bool,
    pub ipv6available: bool,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    pub referral_ns_soa: bool,
}

#[doc = "Check Nameserver IP Addresses and PTR records for a domain"]
#[derive(SimpleObject, Debug)]
pub struct NSAddresses {
    pub ip: String,
    pub ptr: String,
    pub referral_ns_soa: bool,
    pub operational: bool,
    pub authoritative: bool,
    pub recursive: bool,
    pub udp: bool,
    pub tcp: bool,
}

#[doc = "SOA Record information for a domain"]
#[derive(SimpleObject)]
pub struct SOARecord {
    pub primary_ns: String,
    pub contact: String,
    pub serial: String,
    pub refresh: String,
    pub retry: String,
    pub expire: String,
    pub cache_ttl: String,
    pub soa_ttl: String,
}

#[doc = "Check if DNSSEC is enabled for a domain"]
#[derive(SimpleObject)]
pub struct DNSSEC {
    pub dnssec_enabled: bool,
}

#[doc = "Nameserver information for a domain"]
#[derive(SimpleObject)]
pub struct NSRecord {
    pub name: String,
    pub records: Vec<NSARecords>,
    pub nsaddresses: Vec<NSAddresses>,
    pub soa: SOARecord,
}

#[derive(SimpleObject)]
pub struct NSRecords {
    pub ns_records: Vec<NSRecord>,
}

#[derive(SimpleObject)]
pub struct DomainCheckResult {
    dns_records: Vec<DnsRecord>,
    check_caa: CheckCAA,
}

#[derive(SimpleObject)]
pub struct Mx {
    pub name: String,
    pub ipv4: String,
    pub ipv6: String,
    pub ptr: String,
    pub preference: i8,
    pub dnssec: bool,
}
#[derive(SimpleObject)]
pub struct Email {
    pub mx: Vec<Mx>,
}
#[derive(Default)]
pub struct QueryRoot;

pub type BrightSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;
