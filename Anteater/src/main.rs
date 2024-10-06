use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::{TcpStream, UdpSocket};
use tokio::task;
use tokio::time::{timeout, Duration};
use bpaf::Bpaf;
use std::fs::File;
use std::io::Write as IoWrite;
use dns_lookup::lookup_host;
use futures::stream::{self, StreamExt};
use ipnetwork::IpNetwork;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use std::time::Instant;
use pnet::datalink;

const MAX: u16 = 65535;
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
const RATE_LIMIT_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    ip: IpAddr,
    port: u16,
    protocol: Protocol,
    state: PortState,
    service: Option<String>,
    banner: Option<String>,
    latency: u64,  // in milliseconds
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Protocol {
    TCP,
    UDP,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    name: String,
    description: String,
    common_banners: Vec<String>,
}

#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    #[bpaf(long("target"), short('t'), argument("Target"))]
    pub target: String,  // Can be IP, hostname, or CIDR notation
    
    #[bpaf(
        long("start-port"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    pub start_port: u16,
    
    #[bpaf(
        long("end-port"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    pub end_port: u16,
    
    #[bpaf(
        long("timeout"),
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
    
    #[bpaf(long("json-output"), short('j'))]
    pub json_output: bool,
    
    #[bpaf(long("service-detection"), short('d'))]
    pub detect_services: bool,
    
    #[bpaf(long("banner-grabbing"), short('b'))]
    pub grab_banners: bool,
    
    #[bpaf(long("udp"), short('u'))]
    pub scan_udp: bool,
    
    #[bpaf(long("interface"), short('i'), argument("Network Interface"))]
    pub interface: Option<String>,
    
    #[bpaf(long("rate-limit"), argument("Packets per second"), fallback(100u32))]
    pub rate_limit: u32,
    
    #[bpaf(long("ipv6"), short('6'))]
    pub use_ipv6: bool,
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

async fn scan_tcp(ip: IpAddr, port: u16, timeout_duration: u64, grab_banner: bool) -> ScanResult {
    let start_time = Instant::now();
    let addr = SocketAddr::new(ip, port);
    
    let result = timeout(Duration::from_secs(timeout_duration), TcpStream::connect(&addr)).await;
    
    match result {
        Ok(Ok(mut stream)) => {
            let mut banner = None;
            if grab_banner {
                let mut buffer = vec![0; 1024];
                if let Ok(Ok(n)) = timeout(
                    Duration::from_secs(1),
                    stream.read(&mut buffer)
                ).await {
                    if n > 0 {
                        banner = String::from_utf8_lossy(&buffer[..n]).to_string().into();
                    }
                }
            }
            
            ScanResult {
                ip,
                port,
                protocol: Protocol::TCP,
                state: PortState::Open,
                service: get_service_name(port),
                banner,
                latency: start_time.elapsed().as_millis() as u64,
            }
        },
        _ => ScanResult {
            ip,
            port,
            protocol: Protocol::TCP,
            state: PortState::Closed,
            service: None,
            banner: None,
            latency: 0,
        },
    }
}

async fn scan_udp(ip: IpAddr, port: u16, timeout_duration: u64) -> ScanResult {
    let start_time = Instant::now();
    let addr = SocketAddr::new(ip, port);
    
    // Bind to a random local port
    if let Ok(socket) = UdpSocket::bind("0.0.0.0:0").await {
        let mut buffer = vec![0; 1024];
        if socket.send_to(&[0; 10], &addr).await.is_ok() {
            match timeout(
                Duration::from_secs(timeout_duration),
                socket.recv_from(&mut buffer)
            ).await {
                Ok(Ok(_)) => ScanResult {
                    ip,
                    port,
                    protocol: Protocol::UDP,
                    state: PortState::Open,
                    service: get_service_name(port),
                    banner: None,
                    latency: start_time.elapsed().as_millis() as u64,
                },
                _ => ScanResult {
                    ip,
                    port,
                    protocol: Protocol::UDP,
                    state: PortState::Filtered,
                    service: None,
                    banner: None,
                    latency: 0,
                },
            }
        } else {
            ScanResult {
                ip,
                port,
                protocol: Protocol::UDP,
                state: PortState::Closed,
                service: None,
                banner: None,
                latency: 0,
            }
        }
    } else {
        ScanResult {
            ip,
            port,
            protocol: Protocol::UDP,
            state: PortState::Closed,
            service: None,
            banner: None,
            latency: 0,
        }
    }
}

fn get_service_name(port: u16) -> Option<String> {
    // This could be expanded to load from a JSON file or database
    lazy_static::lazy_static! {
        static ref SERVICE_DATABASE: HashMap<u16, ServiceInfo> = {
            let mut m = HashMap::new();
            m.insert(80, ServiceInfo {
                name: "HTTP".to_string(),
                description: "Hypertext Transfer Protocol".to_string(),
                common_banners: vec![
                    "Apache".to_string(),
                    "nginx".to_string(),
                    "Microsoft-IIS".to_string(),
                ],
            });
            // Add more services...
            m
        };
    }
    
    SERVICE_DATABASE.get(&port).map(|info| info.name.clone())
}

async fn resolve_targets(target: String, use_ipv6: bool) -> Result<Vec<IpAddr>, String> {
    // Try parsing as CIDR first
    if let Ok(network) = target.parse::<IpNetwork>() {
        return Ok(network.iter().collect());
    }
    
    // Try parsing as IP address
    if let Ok(ip) = target.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    
    // Try resolving as hostname
    match lookup_host(&target) {
        Ok(ips) => {
            let filtered_ips: Vec<IpAddr> = ips.into_iter()
                .filter(|ip| use_ipv6 || ip.is_ipv4())
                .collect();
            
            if filtered_ips.is_empty() {
                Err("No applicable IP addresses found".to_string())
            } else {
                Ok(filtered_ips)
            }
        }
        Err(e) => Err(format!("Failed to resolve hostname: {}", e)),
    }
}

fn get_interface(interface_name: Option<String>) -> Result<String, String> {
    match interface_name {
        Some(name) => {
            if datalink::interfaces().iter().any(|iface| iface.name == name) {
                Ok(name)
            } else {
                Err(format!("Interface {} not found", name))
            }
        }
        None => {
            datalink::interfaces()
                .into_iter()
                .find(|iface| iface.is_up() && !iface.is_loopback())
                .map(|iface| iface.name)
                .ok_or_else(|| "No suitable network interface found".to_string())
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let opts = arguments().run();
    
    // Validate and get network interface
    let interface = get_interface(opts.interface)?;
    println!("Using network interface: {}", interface);
    
    // Resolve targets
    let targets = resolve_targets(opts.target.clone(), opts.use_ipv6).await?;
    println!("Scanning {} target(s)", targets.len());
    
    if opts.start_port > opts.end_port {
        return Err("Start port must be less than or equal to end port".into());
    }
    
    let (tx, rx) = channel();
    let rate_limiter = Arc::new(RateLimiter::new(opts.rate_limit));
    
    println!("Starting scan...");
    
    let scan_futures = targets.iter().flat_map(|&ip| {
        (opts.start_port..=opts.end_port).flat_map(move |port| {
            let mut futures = vec![];
            
            // TCP scan
            let tcp_future = {
                let tx = tx.clone();
                let rate_limiter = Arc::clone(&rate_limiter);
                async move {
                    rate_limiter.acquire().await;
                    let result = scan_tcp(ip, port, opts.timeout, opts.grab_banners).await;
                    tx.send(result).unwrap_or_else(|e| eprintln!("Failed to send result: {}", e));
                }
            };
            futures.push(tcp_future);
            
            // UDP scan if requested
            if opts.scan_udp {
                let udp_future = {
                    let tx = tx.clone();
                    let rate_limiter = Arc::clone(&rate_limiter);
                    async move {
                        rate_limiter.acquire().await;
                        let result = scan_udp(ip, port, opts.timeout).await;
                        tx.send(result).unwrap_or_else(|e| eprintln!("Failed to send result: {}", e));
                    }
                };
                futures.push(udp_future);
            }
            
            futures
        })
    });
    
    stream::iter(scan_futures)
        .buffer_unordered(opts.concurrency)
        .collect::<Vec<()>>()
        .await;
    
    drop(tx);
    
    let results: Vec<ScanResult> = rx.into_iter().collect();
    
    // Process and output results
    output_results(&results, &opts)?;
    
    Ok(())
}

fn output_results(results: &[ScanResult], opts: &Arguments) -> Result<(), Box<dyn std::error::Error>> {
    let open_results: Vec<&ScanResult> = results.iter()
        .filter(|r| matches!(r.state, PortState::Open))
        .collect();
    
    println!("\nScan complete! Found {} open ports:", open_results.len());
    
    for result in &open_results {
        let service_str = result.service.as_ref().map_or("".to_string(), |s| format!(" ({s})"));
        let banner_str = result.banner.as_ref().map_or("".to_string(), |b| format!(" - Banner: {}", b));
        println!(
            "{}:{} is open [{:?}]{}{} - latency: {}ms",
            result.ip, result.port, result.protocol, service_str, banner_str, result.latency
        );
    }
    
    if let Some(output_file) = &opts.output_file {
        if opts.json_output {
            let json = serde_json::to_string_pretty(&open_results)?;
            std::fs::write(output_file, json)?;
        } else {
            let mut file = File::create(output_file)?;
            writeln!(file, "Port Scan Results:")?;
            for result in &open_results {
                let service_str = result.service.as_ref().map_or("".to_string(), |s| format!(" ({s})"));
                let banner_str = result.banner.as_ref().map_or("".to_string(), |b| format!(" - Banner: {}", b));
                writeln!(
                    file,
                    "{}:{} is open [{:?}]{}{} - latency: {}ms",
                    result.ip, result.port, result.protocol, service_str, banner_str, result.latency
                )?;
            }
        }
        println!("Results have been saved to file: {}", output_file);
    }
    
    Ok(())
}

struct RateLimiter {
    tokens: Arc<Mutex<u32>>,
    rate: u32,
}

impl RateLimiter {
    fn new(rate: u32) -> Self {
        let limiter = RateLimiter {
            tokens: Arc::new(Mutex::new(rate)),
            rate,
        };
        
        let tokens_clone = Arc::clone(&limiter.tokens);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(RATE_LIMIT_INTERVAL);
            loop {
                interval.tick().await;
                let mut tokens = tokens_clone.lock().await;
                *tokens = rate;
            }
        });
        
        limiter
    }
    
   async fn acquire(&self) {
        loop {
            let mut tokens = self.tokens.lock().await;
            if *tokens > 0 {
                *tokens -= 1;
                break;
            }
            drop(tokens);
            tokio::time::sleep(RATE_LIMIT_INTERVAL).await;
        }
    }
}

// Utility function to estimate scan time
fn estimate_scan_time(targets: &[IpAddr], start_port: u16, end_port: u16, scan_udp: bool, concurrency: usize) -> Duration {
    let total_ports = (end_port - start_port + 1) as usize;
    let total_ips = targets.len();
    let total_scans = total_ports * total_ips * if scan_udp { 2 } else { 1 };
    let scans_per_second = concurrency as f64;
    let seconds = (total_scans as f64 / scans_per_second).ceil();
    Duration::from_secs(seconds as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_tcp_scan() {
        let result = scan_tcp(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            80,
            1,
            false
        ).await;
        
        // Assert the result based on your local environment
        assert!(matches!(result.protocol, Protocol::TCP));
    }

    #[tokio::test]
    async fn test_udp_scan() {
        let result = scan_udp(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            53,
            1
        ).await;
        
        assert!(matches!(result.protocol, Protocol::UDP));
    }
    
    #[test]
    fn test_rate_limiter() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let limiter = RateLimiter::new(10);
            for _ in 0..10 {
                limiter.acquire().await;
            }
        });
    }
}

//Author: Morteza Farrokhnejad