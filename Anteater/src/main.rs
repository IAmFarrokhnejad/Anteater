use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;

use bpaf::Bpaf;

const MAX: u16 = 65535; //maximum sniffable port

//Since the user is able to specify an address that can potentially fail, we'll have a fallback address for the sniffer to fallback to.
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

// CLI Arguments.
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]


pub struct Arguments {
    // Address argument.  Accepts -a and --address and an IpAddr type. Falls back to the above constant.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
    /// The address that you want to sniff.  Must be a valid ipv4 address.  Falls back to loopback address
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
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}

async fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr) {

    match TcpStream::connect(format!("{}:{}", addr, start_port)).await {
        // If the connection is successful, print out a dot and then pass the port through the channel.
        Ok(_) => {
            print!(".");
            io::stdout().flush().unwrap();
            tx.send(start_port).unwrap();
        }
        // If the connection is unsuccessful, do nothing.(port is not open)
        Err(_) => {}
    }
}

#[tokio::main]
async fn main() {
  
    let opts = arguments().run();
    // Channel initialization
    let (tx, rx) = channel();

    for i in opts.start_port..opts.end_port {
        let tx = tx.clone();

        task::spawn(async move { scan(tx, i, opts.address).await });
    }

    // Create the vector for all of the outputs.
    let mut out = vec![];
    // Drop the tx clones.
    drop(tx);
    // Wait for all of the outputs to finish and push them into the vector.

    for p in rx {
        out.push(p);
    }

    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}