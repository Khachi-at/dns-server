use std::{
    collections::VecDeque,
    io::Write,
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    sync::{
        atomic::Ordering,
        mpsc::{channel, Sender},
        Arc, Condvar, Mutex,
    },
    thread::Builder,
};

use derive_more::{Display, Error, From};
use rand::random;

use crate::dns::{
    buffer::StreamPacketBuffer,
    netutils::{read_packet_length, write_packet_length},
};

use super::{
    buffer::{BytePacketBuffer, PacketBuffer, VectorPacketBuffer},
    context::ServerContext,
    protocol::{DnsPacket, DnsRecord, QueryType, ResultCode},
    resolve::DnsResolver,
};

#[derive(Debug, Display, Error, From)]
pub enum ServerError {
    Io(std::io::Error),
}

type Result<T> = std::result::Result<T, ServerError>;

macro_rules! return_or_report {
    ($x:expr,$message:expr) => {
        match $x {
            Ok(res) => res,
            Err(_) => {
                println!($message);
                return;
            }
        }
    };
}

macro_rules! ignore_or_report {
    ($x:expr, $message:expr) => {
        match $x {
            Ok(_) => {}
            Err(_) => {
                println!($message);
                return;
            }
        }
    };
}

/// Common trait for DNS servers.
pub trait DnsServer {
    /// Initialize the server and start listening
    ///
    /// This method should _NOT_ block.Rather, servers are expected to
    /// spawn a new thread to handle requests and return immediately.
    fn run_server(self) -> Result<()>;
}

/// Utility function for resolving domains referenced in for example CNAME or SRV
/// records. This usually spares the client form having to perform additional
/// lookups.
fn resolve_cnames(
    lookup_list: &[DnsRecord],
    results: &mut Vec<DnsPacket>,
    resolver: &mut Box<dyn DnsResolver>,
    depth: u16,
) {
    if depth > 10 {
        return;
    }
    for ref rec in lookup_list {
        match **rec {
            DnsRecord::CNAME { ref host, .. } | DnsRecord::SRV { ref host, .. } => {
                if let Ok(result2) = resolver.resolve(host, QueryType::A, true) {
                    let new_unmatched = result2.get_unresolved_cnames();
                    results.push(result2);
                    resolve_cnames(&new_unmatched, results, resolver, depth + 1);
                }
            }
            _ => {}
        }
    }
}

// Perform the actual work for a query.
pub fn execute_query(context: Arc<ServerContext>, request: &DnsPacket) -> DnsPacket {
    let mut packet = DnsPacket::new();
    packet.header.id = request.header.id;
    packet.header.recursion_available = context.allow_recursive;
    packet.header.response = true;

    if request.header.recursion_desired && !context.allow_recursive {
        packet.header.rescode = ResultCode::REFUSED;
    } else if request.questions.is_empty() {
        packet.header.rescode = ResultCode::FORMERR;
    } else {
        let mut results = Vec::new();
        let question = &request.questions[0];
        packet.questions.push(question.clone());
        let mut resolver = context.create_resolver(context.clone());
        let rescode = match resolver.resolve(
            &question.name,
            question.qtype,
            request.header.recursion_desired,
        ) {
            Ok(result) => {
                let rescode = result.header.rescode;
                let unmatched = result.get_unresolved_cnames();
                results.push(result);
                resolve_cnames(&unmatched, &mut results, &mut resolver, 0);
                rescode
            }
            Err(err) => {
                println!(
                    "Failed to resolve {:?} {}: {:?}",
                    question.qtype, question.name, err
                );
                ResultCode::SERVFAIL
            }
        };
        packet.header.rescode = rescode;
        for result in results {
            for rec in result.answers {
                packet.answers.push(rec);
            }
            for rec in result.authorities {
                packet.authorities.push(rec);
            }
            for rec in result.resources {
                packet.resources.push(rec);
            }
        }
    }
    packet
}

/// The UDP server.
pub struct DnsUdpServer {
    context: Arc<ServerContext>,
    request_queue: Arc<Mutex<VecDeque<(SocketAddr, DnsPacket)>>>,
    request_cond: Arc<Condvar>,
    thread_count: usize,
}

impl DnsUdpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsUdpServer {
        DnsUdpServer {
            context: context,
            request_queue: Arc::new(Mutex::new(VecDeque::new())),
            request_cond: Arc::new(Condvar::new()),
            thread_count: thread_count,
        }
    }
}

impl DnsServer for DnsUdpServer {
    /// Launch the server.
    fn run_server(self) -> Result<()> {
        // Bind the socket.
        let socket = UdpSocket::bind(("0.0.0.0", self.context.dns_port))?;
        // Spawn threads for handling requests.
        for thread_id in 0..self.thread_count {
            let socket_clone = match socket.try_clone() {
                Ok(x) => x,
                Err(e) => {
                    println!("Failed to clone socket when starting UDP server: {:?}", e);
                    continue;
                }
            };

            let context = self.context.clone();
            let request_cond = self.request_cond.clone();
            let request_queue = self.request_queue.clone();

            let name = "DnsUdpServer-request-".to_string() + &thread_id.to_string();
            let _ = Builder::new().name(name).spawn(move || {
                loop {
                    // Acquire lock, and wait on the condition util data is
                    // available. Then proceed with popping an entry of the queue.
                    let (src, request) = match request_queue
                        .lock()
                        .ok()
                        .and_then(|x| request_cond.wait(x).ok())
                        .and_then(|mut x| x.pop_front())
                    {
                        Some(x) => x,
                        None => {
                            println!("Not expected to happen!");
                            continue;
                        }
                    };
                    let mut size_limit = 512;

                    // Check for ENDS
                    if request.resources.len() == 1 {
                        if let DnsRecord::OPT { packet_len, .. } = request.resources[0] {
                            size_limit = packet_len as usize;
                        }
                    }

                    // Create a response buffer, and ask the context for an appropriate
                    // resolver.
                    let mut res_buffer = VectorPacketBuffer::new();
                    let mut packet = execute_query(context.clone(), &request);
                    let _ = packet.write(&mut res_buffer, size_limit);

                    // Fire off the response.
                    let len = res_buffer.pos();
                    let data = return_or_report!(
                        res_buffer.get_range(0, len),
                        "Failed to get buffer data"
                    );
                    ignore_or_report!(
                        socket_clone.send_to(data, src),
                        "Failed to send response packet"
                    );
                }
            })?;
        }

        // Start servicing requests.
        let _ = Builder::new()
            .name("DnsUdpServer-incoming".into())
            .spawn(move || loop {
                let _ = self
                    .context
                    .statistics
                    .udp_query_count
                    .fetch_add(1, Ordering::Release);
                let mut req_buffer = BytePacketBuffer::new();
                let (_, src) = match socket.recv_from(&mut req_buffer.buf) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("Failed to read from UDP socket: {:?}", e);
                        continue;
                    }
                };

                // Parse it.
                let request = match DnsPacket::from_buffer(&mut req_buffer) {
                    Ok(x) => x,
                    Err(e) => {
                        println!("Failed to parse UDP query packet: {:?}", e);
                        continue;
                    }
                };

                // Acquire lock, add request to queue, and notify waiting threads
                // using the condition.
                match self.request_queue.lock() {
                    Ok(mut queue) => {
                        queue.push_back((src, request));
                        self.request_cond.notify_one();
                    }
                    Err(e) => {
                        println!("Failed to send UDP request for processing: {}", e);
                    }
                }
            })?;
        Ok(())
    }
}

/// TCP DNS server
pub struct DnsTcpServer {
    context: Arc<ServerContext>,
    senders: Vec<Sender<TcpStream>>,
    thread_count: usize,
}

impl DnsTcpServer {
    pub fn new(context: Arc<ServerContext>, thread_count: usize) -> DnsTcpServer {
        DnsTcpServer {
            context: context,
            senders: Vec::new(),
            thread_count: thread_count,
        }
    }
}

impl DnsServer for DnsTcpServer {
    fn run_server(mut self) -> Result<()> {
        let socket = TcpListener::bind(("0.0.0.0", self.context.dns_port))?;

        // Spawn threads for handling requests, and create the channels.
        for thread_id in 0..self.thread_count {
            let (tx, rx) = channel();
            self.senders.push(tx);
            let context = self.context.clone();
            let name = "DnsTcpServer-request-".to_string() + &thread_id.to_string();
            let _ = Builder::new().name(name).spawn(move || loop {
                let mut stream = match rx.recv() {
                    Ok(x) => x,
                    Err(_) => continue,
                };

                let _ = context
                    .statistics
                    .tcp_query_count
                    .fetch_add(1, Ordering::Release);
                ignore_or_report!(
                    read_packet_length(&mut stream),
                    "Failed to read query packet length"
                );

                let request = {
                    let mut stream_buffer = StreamPacketBuffer::new(&mut stream);
                    return_or_report!(
                        DnsPacket::from_buffer(&mut stream_buffer),
                        "Failed to read query packet"
                    )
                };

                let mut res_buffer = VectorPacketBuffer::new();
                let mut packet = execute_query(context.clone(), &request);
                ignore_or_report!(
                    packet.write(&mut res_buffer, 0xFFFF),
                    "Failed to write packet to buffer"
                );
                let len = res_buffer.pos();
                ignore_or_report!(
                    write_packet_length(&mut stream, len),
                    "Failed to write packet size"
                );

                let data =
                    return_or_report!(res_buffer.get_range(0, len), "Failed to get packet data");
                ignore_or_report!(stream.write(data), "Failed to write response packet");
                ignore_or_report!(stream.shutdown(Shutdown::Both), "Failed to shutdown socket");
            })?;
        }

        let _ = Builder::new()
            .name("DnsTcpServer-incoming".into())
            .spawn(move || {
                for wrap_stream in socket.incoming() {
                    let stream = match wrap_stream {
                        Ok(stream) => stream,
                        Err(err) => {
                            println!("Failed to accept TCP connection: {:?}", err);
                            continue;
                        }
                    };
                    let thread_no = random::<usize>() % self.thread_count;
                    match self.senders[thread_no].send(stream) {
                        Ok(_) => {}
                        Err(e) => {
                            println!(
                                "Failed to send TCP request for processing on thread {}:{}",
                                thread_no, e
                            );
                        }
                    }
                }
            })?;

        Ok(())
    }
}
