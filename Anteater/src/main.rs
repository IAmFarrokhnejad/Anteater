use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;
use tokio::time::{timeout, Duration};
use bpaf::Bpaf;
use std::fs::File;
use std::io::Write as IoWrite;
use dns_lookup::lookup_host;
use futures::stream::{self, StreamExt};

const MAX: u16 = 65535;
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

#[derive(Debug, Clone)]
pub struct ScanResult {
    port: u16,
    service: Option<String>,
    latency: Duration,
}

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    #[bpaf(long("address"), short('a'), argument("Address"), fallback(IPFALLBACK))]
    pub address: String,  // Changed to String to support hostnames
    
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    pub start_port: u16,
    
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    pub end_port: u16,
    
    #[bpaf(
        long("timeout"),
        short('t'),
        argument("Timeout"),
        fallback(3u64)
    )]
    pub timeout: u64,
    
    #[bpaf(
        long("concurrency"),
        short('c'),
        argument("Concurrency"),
        fallback(100usize)
    )]
    pub concurrency: usize,
    
    #[bpaf(long("output"), short('o'), argument("Output File"))]
    pub output_file: Option<String>,
    
    #[bpaf(long("service-detection"), short('d'))]
    pub detect_services: bool,
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

async fn scan(tx: Sender<ScanResult>, port: u16, addr: IpAddr, timeout_duration: u64, detect_services: bool) {
    let start_time = std::time::Instant::now();
    let result = timeout(Duration::from_secs(timeout_duration), TcpStream::connect((addr, port))).await;
    
    match result {
        Ok(Ok(_)) => {
            let latency = start_time.elapsed();
            let mut service = None;
            
            if detect_services {
                service = get_service_name(port);
            }
            
            print!(".");
            io::stdout().flush().unwrap();
            
            let scan_result = ScanResult {
                port,
                service,
                latency,
            };
            
            tx.send(scan_result).unwrap_or_else(|e| eprintln!("Failed to send result for port {}: {}", port, e));
        }
        _ => {}
    }
}

fn get_service_name(port: u16) -> Option<String> {
    // This is a basic implementation. You might want to expand this with a more comprehensive database
    match port {
        80 => Some("HTTP".to_string()),
        443 => Some("HTTPS".to_string()),
        22 => Some("SSH".to_string()),
        21 => Some("FTP".to_string()),
        25 => Some("SMTP".to_string()),
        // Add more port-to-service mappings as needed
        _ => None,
    }
}

async fn resolve_address(address: String) -> Result<IpAddr, String> {
    // If the address is already an IP, parse it directly
    if let Ok(ip) = address.parse::<IpAddr>() {
        return Ok(ip);
    }
    
    // Otherwise, try to resolve it as a hostname
    match lookup_host(&address) {
        Ok(ips) => ips.first()
            .ok_or_else(|| "No IP addresses found".to_string())
            .map(|ip| *ip),
        Err(e) => Err(format!("Failed to resolve hostname: {}", e)),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = arguments().run();
    
    // Resolve the address
    let addr = resolve_address(opts.address.clone()).await?;
    println!("Scanning address: {}", addr);
    
    if opts.start_port > opts.end_port {
        eprintln!("Start port must be less than or equal to end port");
        return Ok(());
    }
    
    let (tx, rx) = channel();
    
    println!("Starting scan of ports {} to {} ...", opts.start_port, opts.end_port);
    
    let ports: Vec<u16> = (opts.start_port..=opts.end_port).collect();
    
    stream::iter(ports)
        .map(|port| {
            let tx = tx.clone();
            let addr = addr;
            let timeout_duration = opts.timeout;
            let detect_services = opts.detect_services;
            
            async move {
                scan(tx, port, addr, timeout_duration, detect_services).await;
            }
        })
        .buffer_unordered(opts.concurrency)
        .collect::<Vec<()>>()
        .await;
    
    drop(tx);
    
    let mut results: Vec<ScanResult> = rx.into_iter().collect();
    results.sort_by_key(|r| r.port);
    
    println!("\nScan complete! Found {} open ports:", results.len());
    
    for result in &results {
        let service_str = result.service.as_ref().map_or("".to_string(), |s| format!(" ({s})"));
        println!("Port {} is open{} - latency: {:?}", result.port, service_str, result.latency);
    }
    
    if let Some(output_file) = opts.output_file {
        let mut file = File::create(output_file)?;
        writeln!(file, "Port Scan Results for {}:", addr)?;
        for result in &results {
            let service_str = result.service.as_ref().map_or("".to_string(), |s| format!(" ({s})"));
            writeln!(file, "Port {} is open{} - latency: {:?}", result.port, service_str, result.latency)?;
        }
        println!("Results have been saved to file.");
    }
    
    Ok(())
}

//Author: Morteza Farrokhnejad
