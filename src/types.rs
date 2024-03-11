use async_graphql::SimpleObject;
use std::sync::Arc;

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
#[derive(SimpleObject)]
pub struct CheckCAA {
    pub has_policy: bool,
    pub has_policy_reporting: bool,
}

#[derive(Default)]
pub struct DomainCheck {
    pub domain: Arc<String>,
}

#[derive(SimpleObject)]
pub struct DomainCheckResult {
    dns_records: Vec<DnsRecord>,
    check_caa: CheckCAA,
}
#[derive(Default)]
pub struct QueryRoot;
