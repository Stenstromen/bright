use std::sync::Arc;
use async_graphql::{ SimpleObject, Schema, EmptyMutation, EmptySubscription };

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
pub struct CAARecords {
    pub name: String,
    pub caa_type: String,
    pub data: String,
}

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

#[derive(SimpleObject)]
pub struct DomainCheckResult {
    dns_records: Vec<DnsRecord>,
    check_caa: CheckCAA,
}
#[derive(Default)]
pub struct QueryRoot;

pub type BrightSchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;
