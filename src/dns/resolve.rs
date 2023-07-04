use std::sync::Arc;

use derive_more::{Display, Error, From};

use super::{
    context::ServerContext,
    protocol::{DnsPacket, QueryType, ResultCode},
};

#[derive(Debug, Display, From, Error)]
pub enum ResolveError {
    Client(crate::dns::client::ClientError),
    Cache(crate::dns::cache::CacheError),
    Io(std::io::Error),
    NoServerFound,
}

type Result<T> = std::result::Result<T, ResolveError>;

pub trait DnsResolver {
    fn get_context(&self) -> Arc<ServerContext>;

    fn resolve(&mut self, qname: &str, qtype: QueryType, recursive: bool) -> Result<DnsPacket> {
        if let QueryType::UNKNOWN(_) = qtype {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::NOTIMP;
            return Ok(packet);
        }
        let context = self.get_context();

        if let Some(qr) = context.authority.query(qname, qtype) {
            return Ok(qr);
        }
        if !recursive || !context.allow_recursive {
            let mut packet = DnsPacket::new();
            packet.header.rescode = ResultCode::REFUSED;
            return Ok(packet);
        }
        if let Some(qr) = context.cache.lookup(qname, qtype) {
            return Ok(qr);
        }
        if qtype == QueryType::A || qtype == QueryType::AAAA {
            if let Some(qr) = context.cache.lookup(qname, QueryType::CNAME) {
                return Ok(qr);
            }
        }

        self.perform(qname, qtype)
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket>;
}

/// A Forwarding DNS Resolver
///
/// This resolver uses an external DNS server to service a query.
pub struct ForwardingDnsResolver {
    context: Arc<ServerContext>,
    server: (String, u16),
}

impl ForwardingDnsResolver {
    pub fn new(context: Arc<ServerContext>, server: (String, u16)) -> ForwardingDnsResolver {
        ForwardingDnsResolver {
            context: context,
            server: server,
        }
    }
}

impl DnsResolver for ForwardingDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        let &(ref host, port) = &self.server;
        let result = self
            .context
            .client
            .send_query(qname, qtype, (host.as_str(), port), true)?;

        self.context.cache.store(&result.answers)?;
        Ok(result)
    }
}

/// A Recursive DNS resolver
///
/// This resolver can answer any request using the root servers of the internet
pub struct RecursiveDnsResolver {
    context: Arc<ServerContext>,
}

impl RecursiveDnsResolver {
    pub fn new(context: Arc<ServerContext>) -> RecursiveDnsResolver {
        RecursiveDnsResolver { context: context }
    }
}

impl DnsResolver for RecursiveDnsResolver {
    fn get_context(&self) -> Arc<ServerContext> {
        self.context.clone()
    }

    fn perform(&mut self, qname: &str, qtype: QueryType) -> Result<DnsPacket> {
        // Find the closest name server by splitting the label and progessively
        // moving towards the root servers.I.e check "google.com", then "com",
        // and finally.
        let mut tentative_ns = None;
        let labels = qname.split('.').collect::<Vec<&str>>();
        for lbl_idx in 0..labels.len() + 1 {
            let domain = labels[lbl_idx..].join(".");
            match self
                .context
                .cache
                .lookup(&domain, QueryType::NS)
                .and_then(|qr| qr.get_unresolved_ns(&domain))
                .and_then(|ns| self.context.cache.lookup(&ns, QueryType::A))
                .and_then(|qr| qr.get_random_a())
            {
                Some(addr) => {
                    tentative_ns = Some(addr);
                    break;
                }
                None => continue,
            }
        }
        let mut ns = tentative_ns.ok_or_else(|| ResolveError::NoServerFound)?;

        // Start querying name servers.
        loop {
            println!("attempting lookup of {:?} {} with ns {}", qtype, qname, ns);
            let ns_copy = ns.clone();
            let server = (ns_copy.as_str(), 53);
            let response = self
                .context
                .client
                .send_query(qname, qtype.clone(), server, false)?;

            // If we've got an actual answer, we're down!
            if !response.answers.is_empty() && response.header.rescode == ResultCode::NOERROR {
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);
                return Ok(response.clone());
            }

            if response.header.rescode == ResultCode::NXDOMAIN {
                if let Some(ttl) = response.get_ttl_from_soa() {
                    let _ = self.context.cache.store_nxdomain(qname, qtype, ttl);
                }
                return Ok(response.clone());
            }
            if let Some(new_ns) = response.get_resolved_ns(qname) {
                ns = new_ns.clone();
                let _ = self.context.cache.store(&response.answers);
                let _ = self.context.cache.store(&response.authorities);
                let _ = self.context.cache.store(&response.resources);
                continue;
            }
            let new_ns_name = match response.get_resolved_ns(qname) {
                Some(x) => x,
                None => return Ok(response.clone()),
            };

            let recursive_response = self.resolve(&new_ns_name, QueryType::A, true)?;
            if let Some(new_ns) = recursive_response.get_random_a() {
                ns = new_ns.clone()
            } else {
                return Ok(response.clone());
            }
        }
    }
}
