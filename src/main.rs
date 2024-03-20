mod types;
mod dns;
mod graphql;
use types::QueryRoot;
use graphql::graphql_handler;

use warp::Filter;
use async_graphql::{ Schema, EmptyMutation, EmptySubscription };

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

    let liveness_route = warp
        ::path("status")
        .map(|| warp::reply::json(&"OK"));

    let readiness_route = warp
        ::path("ready")
        .map(|| warp::reply::json(&"OK"));

    let routes = graphql_route
        .or(liveness_route)
        .or(readiness_route);

    warp::serve(routes).run(([0, 0, 0, 0], 8000)).await;
}
