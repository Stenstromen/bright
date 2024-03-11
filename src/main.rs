mod types;
mod dns;
use dns::{ check_caa, dns_records };
use types::{ DnsRecord, DnsRecords, CheckCAA, DomainCheck, QueryRoot };

use std::sync::Arc;
use std::convert::Infallible;

use anyhow::{ Error, Result };
use tokio::task::{ self, JoinError };
use warp::{ Filter, http::Response as HttpResponse, Reply };
use async_graphql::{
    Result as GqlResult,
    Error as GqlError,
    Object,
    Request,
    Response,
    Schema,
    EmptyMutation,
    EmptySubscription,
};

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
        check_caa().map_err(|e: Error| GqlError::new(e.to_string()))
    }
}

#[Object]
impl QueryRoot {
    async fn domain_checks(&self, domain: String) -> GqlResult<DomainCheck> {
        Ok(DomainCheck { domain: Arc::new(domain) })
    }
}

type MySchema = Schema<QueryRoot, EmptyMutation, EmptySubscription>;

async fn graphql_handler(schema: MySchema, req: Request) -> Result<impl Reply, Infallible> {
    let response: Response = schema.execute(req).await;

    Ok(
        HttpResponse::builder()
            .header("content-type", "application/json")
            .body(serde_json::to_string(&response).unwrap())
            .unwrap()
    )
}

#[tokio::main]
async fn main() {
    let schema: Schema<QueryRoot, EmptyMutation, EmptySubscription> = Schema::build(
        QueryRoot,
        EmptyMutation,
        EmptySubscription
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
