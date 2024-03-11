mod types;
use types::{ DnsRecord, DnsRecords, CheckCAA, DomainCheck, QueryRoot };

use std::convert::Infallible;
use std::sync::Arc;

use anyhow::{ Error, Result };
use async_graphql::{ Result as GqlResult, Object, Request, Response, Schema };
use hickory_resolver::config::*;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use tokio::task;
use warp::{ Filter, http::Response as HttpResponse, Reply };

#[Object]
impl DomainCheck {
    async fn dns_records(&self) -> GqlResult<Vec<DnsRecord>> {
        let domain = self.domain.clone();
        let dns_result = task
            ::spawn_blocking(move || { dns_records(&domain) }).await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?
            .map_err(|e: Error| async_graphql::Error::new(e.to_string()))?;

        Ok(dns_result.dns_records)
    }

    async fn check_caa(&self) -> GqlResult<CheckCAA> {
        Ok(CheckCAA {
            has_policy: true,
            has_policy_reporting: false,
        })
    }
}

#[Object]
impl QueryRoot {
    async fn domain_checks(&self, domain: String) -> GqlResult<DomainCheck> {
        Ok(DomainCheck { domain: Arc::new(domain) })
    }
}

type MySchema = Schema<QueryRoot, async_graphql::EmptyMutation, async_graphql::EmptySubscription>;

fn dns_records(domain: &str) -> Result<DnsRecords> {
    let base_record_types = vec![
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

    let srv_subdomains = vec![
        "_sip._tls",
        "_sipfederationtls._tcp",
        "_xmpp-client._tcp",
        "_xmpp-server._tcp"
    ];

    let txt_subdomains = vec!["_dmarc", "_domainkey", "_mta-sts", "_smtp._tls"];

    let resolver = Resolver::new(ResolverConfig::quad9(), ResolverOpts::default())?;

    let mut records = DnsRecords { dns_records: Vec::new() };

    for record_type in &base_record_types {
        if *record_type == RecordType::SRV || *record_type == RecordType::TXT {
            continue;
        }

        check_and_add_record(&resolver, domain, *record_type, &mut records).unwrap();
    }

    let www_domain = format!("www.{}", domain);
    check_and_add_record(&resolver, &www_domain, RecordType::A, &mut records).unwrap();
    check_and_add_record(&resolver, &www_domain, RecordType::AAAA, &mut records).unwrap();

    for subdomain in srv_subdomains {
        let fqdn = format!("{}.{}", subdomain, domain);
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
) -> Result<(), Box<dyn std::error::Error>> {
    let result = resolver.lookup(domain, record_type);
    match result {
        Ok(lookup) => {
            for record in lookup.record_iter() {
                let record_str = record.to_string();
                let parts: Vec<&str> = record_str.split_whitespace().collect();

                let name = parts.get(0).unwrap_or(&"").to_string();
                let ttl = parts.get(1).unwrap_or(&"").to_string();
                let data = parts
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

async fn graphql_handler(schema: MySchema, req: Request) -> Result<impl Reply, Infallible> {
    // Execute the GraphQL request
    let response: Response = schema.execute(req).await;

    // Convert the GraphQL response into a Warp response
    Ok(
        HttpResponse::builder()
            .header("content-type", "application/json")
            .body(serde_json::to_string(&response).unwrap())
            .unwrap()
    )
}

#[tokio::main]
async fn main() {
    let schema = Schema::build(
        QueryRoot,
        async_graphql::EmptyMutation,
        async_graphql::EmptySubscription
    ).finish();

    let schema_filter = warp::any().map(move || schema.clone());

    let graphql_route = warp
        ::post()
        .and(warp::path("graphql"))
        .and(schema_filter)
        .and(warp::body::json())
        .and_then(graphql_handler);

    warp::serve(graphql_route).run(([127, 0, 0, 1], 8000)).await;
}
