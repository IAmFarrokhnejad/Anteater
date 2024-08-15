# Anteater
 A port scanner built using rust.


This Rust program is an asynchronous TCP port scanner designed to identify open ports on a specified IP address. It utilizes the Tokio library for handling asynchronous tasks and the Bpaf library for command-line argument parsing.
Key Features:
- IP Address Scanning: The user can specify an IP address to scan for open ports. If no address is provided, the scanner defaults to the loopback address (127.0.0.1).
- Port Range Specification: The user can define a start and end port for scanning. The scanner iterates through this range and checks each port.
- Concurrency Control: The program allows the user to control the number of concurrent port scans, helping manage system resources.
- Timeout Handling: Each port scan has a configurable timeout, preventing the scanner from hanging on unresponsive ports.
- Output: The program prints a dot for each open port found and lists all open ports at the end of the scan.
