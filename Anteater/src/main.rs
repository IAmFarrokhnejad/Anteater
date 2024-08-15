use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;
use tokio::time::{timeout, Duration};
use bpaf::Bpaf;

const MAX: u16 = 65535; // Maximum sniffable port

// Fallback IP address
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// CLI Arguments
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    /// The address to sniff. Falls back to the loopback address.
    #[bpaf(long("address"), short('a'), argument("Address"), fallback(IPFALLBACK))]
    pub address: IpAddr,

    /// The starting port. Must be greater than 0. Defaults to 1.
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    pub start_port: u16,

    /// The ending port. Must be less than or equal to 65535. Defaults to MAX.
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    pub end_port: u16,

    /// The timeout duration in seconds for each connection attempt. Defaults to 3 seconds.
    #[bpaf(
        long("timeout"),
        short('t'),
        argument("Timeout"),
        fallback(3u64)
    )]
    pub timeout: u64,

    /// The number of concurrent tasks. Defaults to 100.
    #[bpaf(
        long("concurrency"),
        short('c'),
        argument("Concurrency"),
        fallback(100usize)
    )]
    pub concurrency: usize,
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

async fn scan(tx: Sender<u16>, port: u16, addr: IpAddr, timeout_duration: u64) {
    // Set a timeout for the connection attempt
    let result = timeout(Duration::from_secs(timeout_duration), TcpStream::connect((addr, port))).await;

    match result {
        // If the connection is successful, print out a dot and then pass the port through the channel.
        Ok(Ok(_)) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(port).unwrap_or_else(|e| eprintln!("Failed to send port {}: {}", port, e));
        }
        // If the connection fails or times out, do nothing.
        _ => {}
    }
}

#[tokio::main]
async fn main() {
    let opts = arguments().run();

    // Check if start_port is less than or equal to end_port
    if opts.start_port > opts.end_port {
        eprintln!("Start port must be less than or equal to end port");
        return;
    }

    // Channel initialization
    let (tx, rx) = channel();

    let mut tasks = vec![];
    for i in (opts.start_port..=opts.end_port).step_by(opts.concurrency) {
        for port in i..(i + opts.concurrency as u16).min(opts.end_port + 1) {
            let tx = tx.clone();
            let addr = opts.address;
            let timeout_duration = opts.timeout;
            let task = task::spawn(async move {
                scan(tx, port, addr, timeout_duration).await;
            });
            tasks.push(task);
        }
    }

    // Await all tasks to complete
    for task in tasks {
        task.await.unwrap_or_else(|e| eprintln!("Task error: {}", e));
    }

    // Drop the tx clones
    drop(tx);

    // Collect and sort open ports
    let mut out: Vec<u16> = rx.into_iter().collect();
    out.sort();

    println!("\nOpen ports:");
    for v in out {
        println!("{} is open", v);
    }
}