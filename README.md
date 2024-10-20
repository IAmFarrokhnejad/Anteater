# Anteater



This project implements a multi-threaded port scanner in Rust, utilizing asynchronous programming with `Tokio` for concurrency. The scanner supports both TCP and UDP protocols, service detection, banner grabbing, rate limiting, and can handle large scans efficiently by leveraging concurrency controls.

## Key Features

- **Target Resolution**: Supports scanning a target defined by IP address, hostname, or CIDR notation. It also resolves hostnames to IP addresses and supports both IPv4 and IPv6.
- **TCP and UDP Scanning**: The scanner can probe TCP and UDP ports to check if they are open, closed, or filtered. 
- **Banner Grabbing**: Optionally grabs service banners from open ports for further identification.
- **Service Detection**: Attempts to detect common services (like HTTP, FTP) running on specific ports.
- **Rate Limiting**: Implements a custom rate limiter to control the scan speed (packets per second), ensuring scans are not too aggressive.
- **Concurrency**: Configurable concurrency settings allow controlling the number of ports to be scanned simultaneously.
- **Timeouts**: Scans have customizable timeouts for determining port state.
- **Interface Selection**: Supports selecting specific network interfaces for scanning.
- **Output**: Results can be printed to the console or saved to a file in plain text or JSON format.

## Command-Line Arguments

The scanner accepts a wide range of arguments to customize its behavior:

- `--target/-t` (required): Specifies the target (IP, hostname, or CIDR).
- `--start-port/-s`: Starting port for the scan (default is 1).
- `--end-port/-e`: Ending port for the scan (default is 65535).
- `--timeout`: Timeout in seconds for each port scan (default is 3 seconds).
- `--verbose/-v`: Prints detailed information about all ports, including closed ones.
- `--concurrency/-c`: Sets the number of concurrent port scans (default is 100).
- `--output/-o`: File path to save scan results.
- `--json-output/-j`: Outputs scan results in JSON format.
- `--service-detection/-d`: Enables service detection on well-known ports.
- `--banner-grabbing/-b`: Enables grabbing banners from open ports.
- `--udp/-u`: Enables UDP scanning.
- `--interface/-i`: Specifies the network interface to use for scanning.
- `--rate-limit`: Sets the scan rate in packets per second (default is 100).
- `--ipv6/-6`: Enables IPv6 scanning.

## Port Scanning Logic

1. **TCP Scanning**: 
   - The scanner attempts to establish a TCP connection to each target port.
   - If the connection is successful, the port is considered open, and optional banner grabbing is performed.
   - If the connection fails, the port is marked as closed or filtered, depending on the nature of the failure.

2. **UDP Scanning**:
   - A UDP packet is sent to each target port, and the scanner waits for a response.
   - If a response is received, the port is marked as open. Lack of response could indicate the port is filtered or closed.

3. **Service Detection**:
   - The scanner has a built-in database of common services (like HTTP, FTP) associated with well-known ports. This can be expanded to include more services.

4. **Rate Limiting**:
   - The scanner implements a rate limiter that controls how many packets are sent per second. This prevents overwhelming the target network and makes the scan less aggressive.

5. **Concurrency**:
   - The scanner leverages Rust’s asynchronous capabilities to scan multiple ports in parallel, drastically reducing scan time.

## Output

- **Console**: Open ports are printed with details including IP address, port number, protocol (TCP/UDP), service name (if detected), banner (if grabbed), and latency.
- **File Output**: Results can be saved to a specified file in plain text or JSON format.

Example output:

```text
Scan complete! Found 3 open ports:
127.0.0.1:80 is open [TCP] (HTTP) - latency: 35ms
127.0.0.1:443 is open [TCP] (HTTPS) - latency: 30ms
127.0.0.1:53 is open [UDP] (DNS) - latency: 10ms
Results have been saved to file: scan_results.json
