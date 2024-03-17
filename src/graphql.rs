use crate::types::{
    BrightSchema,
    CheckCAA,
    DnsRecord,
    DnsRecords,
    DomainCheck,
    NSRecord,
    QueryRoot,
    DNSSEC,
};
use crate::dns::{ check_caa, check_dnssec, check_ns, dns_records };

use std::sync::Arc;
use std::convert::Infallible;

use anyhow::{ Error, Result };
use tokio::task::{ self, JoinError };
use warp::{ http::Response as HttpResponse, Reply };
use async_graphql::{ Result as GqlResult, Error as GqlError, Object, Request, Response };

#[Object]
impl DomainCheck {
    async fn records(&self) -> GqlResult<Vec<DnsRecord>> {
        let domain: Arc<String> = self.domain.clone();
        let dns_result: DnsRecords = task
            ::spawn_blocking(move || { dns_records(&domain) }).await
            .map_err(|e: JoinError| GqlError::new(e.to_string()))?
            .map_err(|e: Error| GqlError::new(e.to_string()))?;

        Ok(dns_result.dns_records)
    }

    async fn caa(&self) -> GqlResult<CheckCAA> {
        let domain: Arc<String> = self.domain.clone();
        let caa_result: CheckCAA = task
            ::spawn_blocking(move || { check_caa(&domain) }).await
            .map_err(|e: JoinError| GqlError::new(e.to_string()))?
            .map_err(|e: Error| GqlError::new(e.to_string()))?;

        Ok(caa_result)
    }

    async fn ns(&self) -> GqlResult<NSRecord> {
        let domain: Arc<String> = self.domain.clone();
        let ns_result: NSRecord = task
            ::spawn_blocking(move || { check_ns(&domain) }).await
            .map_err(|e: JoinError| GqlError::new(e.to_string()))?
            .map_err(|e: Error| GqlError::new(e.to_string()))?;

        Ok(ns_result)
    }

    async fn dnssec(&self) -> GqlResult<DNSSEC> {
        let domain: Arc<String> = self.domain.clone();
        let dnssec_result: DNSSEC = task
            ::spawn_blocking(move || { check_dnssec(&domain) }).await
            .map_err(|e: JoinError| GqlError::new(e.to_string()))?
            .map_err(|e: Error| GqlError::new(e.to_string()))?;

        Ok(dnssec_result)
    }
}

#[Object]
impl QueryRoot {
    async fn domain_checks(&self, domain: String) -> GqlResult<DomainCheck> {
        Ok(DomainCheck { domain: Arc::new(domain) })
    }
}

pub async fn graphql_handler(schema: BrightSchema, req: Request) -> Result<impl Reply, Infallible> {
    let response: Response = schema.execute(req).await;

    Ok(
        HttpResponse::builder()
            .header("content-type", "application/json")
            .body(serde_json::to_string(&response).unwrap())
            .unwrap()
    )
}
