use serde_derive::{Deserialize, Serialize};

use crate::dns::context::ServerContext;
use crate::web::Result;

#[derive(Serialize, Deserialize)]
pub struct IndexResponse {
    ok: bool,
    client_sent_quires: usize,
    client_failed_quires: usize,
    server_tcp_quires: usize,
    server_udp_quires: usize,
}

pub fn index(context: &ServerContext) -> Result<IndexResponse> {
    Ok(IndexResponse {
        ok: true,
        client_sent_quires: context.client.get_sent_count(),
        client_failed_quires: context.client.get_failed_count(),
        server_tcp_quires: context.statistics.get_tcp_query_count(),
        server_udp_quires: context.statistics.get_udp_query_count(),
    })
}
