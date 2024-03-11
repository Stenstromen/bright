use anyhow::Error;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::Resolver;
use hickory_resolver::config::*;
use async_graphql::{ Object, Schema, SimpleObject };
use std::convert::Infallible;
use warp::{ http::Response as HttpResponse, Filter };
use async_graphql::{ Request, Response, Result as GqlResult, Context };
use warp::Reply;
use tokio::task;
use anyhow::Result;

#[derive(SimpleObject)]
struct DnsRecord {
    name: String,
    ttl: String,
    record_type: String,
    data: String,
}

#[derive(SimpleObject)]
struct DnsRecords {
    dns_records: Vec<DnsRecord>,
}
#[derive(SimpleObject)]
struct CheckCAA {
    has_policy: bool,
    has_policy_reporting: bool,
}

#[derive(SimpleObject)]
struct DomainCheckResult {
    dns_records: Vec<DnsRecord>,
    check_caa: CheckCAA,
}
#[derive(Default)]
struct QueryRoot;

#[Object]
impl QueryRoot {
    #[graphql(name = "domainCheck")]
    async fn domain_check(
        &self,
        ctx: &Context<'_>,
        domain: String
    ) -> GqlResult<DomainCheckResult> {
        let dns_result = task
            ::spawn_blocking(move || dns_records(&domain)).await
            .map_err(|e| async_graphql::Error::new(e.to_string()))?
            .map_err(|e: Error| async_graphql::Error::new(e.to_string()));

        let dns_records = dns_result?.dns_records;

        let check_caa = CheckCAA {
            has_policy: true,
            has_policy_reporting: false,
        };

        let result = DomainCheckResult {
            dns_records,
            check_caa,
        };

        Ok(result)
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

        check_and_add_record(&resolver, domain, *record_type, &mut records);
    }

    let www_domain = format!("www.{}", domain);
    check_and_add_record(&resolver, &www_domain, RecordType::A, &mut records);
    check_and_add_record(&resolver, &www_domain, RecordType::AAAA, &mut records);

    for subdomain in srv_subdomains {
        let fqdn = format!("{}.{}", subdomain, domain);
        check_and_add_record(&resolver, &fqdn, RecordType::SRV, &mut records);
    }

    for subdomain in txt_subdomains {
        let fqdn = format!("{}.{}", subdomain, domain);
        check_and_add_record(&resolver, &fqdn, RecordType::TXT, &mut records);
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
