use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::mpsc::{channel, Sender};
use tokio::net::TcpStream;
use tokio::task;

use bpaf::Bpaf;

const MAX: u16 = 65535; //maximum sniffable port

//Since the user is able to specify an address that can potentially fail, we'll have a fallback address for the sniffer to fallback to.
const IPFALLBACK: IpAddr = IpAddr::V4(Ipv4Addr::new(a:127, b:0, c:0, d:1));

// CLI Arguments.
#[derive(Debug, Clone, Bpaf)]
#[bpaf(options)]
pub struct Arguments {
    // Address argument.  Accepts -a and --address and an IpAddr type. Falls back to the above constant.
    #[bpaf(long, short, argument("Address"), fallback(IPFALLBACK))]
    /// The address that you want to sniff.  Must be a valid ipv4 address.  Falls back to 127.0.0.1
    pub address: IpAddr,
    #[bpaf(
        long("start"),
        short('s'),
        guard(start_port_guard, "Must be greater than 0"),
        fallback(1u16)
    )]
    /// The start port for the sniffer. (must be greater than 0)
    pub start_port: u16,
    #[bpaf(
        long("end"),
        short('e'),
        guard(end_port_guard, "Must be less than or equal to 65535"),
        fallback(MAX)
    )]
    /// The end port for the sniffer. (must be less than or equal to 65535)
    pub end_port: u16,
}

fn start_port_guard(input: &u16) -> bool {
    *input > 0
}

fn end_port_guard(input: &u16) -> bool {
    *input <= MAX
}


fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16)
{
    let mut port: u16 = start_port +1;
    loop
    {
        match TcpStream::connect((addr, port))
        { //passing the IP address and the port number we're currently scanning
        Ok(_) => {
            print!("."); //send back feedback to the user every single time it finds an open port
            io::stdout().flush().unwrap();
            tx.send(port).unwrap(); //It will send back to RX in the main function(Multi-threaded part)
        }
        Err(_) =>{} //return empty expression in case of error

        }

        if (MAX - port) <= num_threads
        {
            break;
        }

        port += num_threads;
    }
}


fn main() 
{
    let args: Vec<String> =env::args().collect();
    let program = args[0].clone();
    let arguments = Arguments::new(&args).unwrap_or_else(
        |err| {
            if err.contains("help")
            {    process::exit(0);}
            else 
            {
                eprintln!("{} Cound not parse the arguments: {}", program, err);
                process::exit(0);
            }
        }
    );


    //multi-threaded
    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;

    let (tx, rx) = channel(); //transmitter and receiver
    //loop to bind tx to another tx variable so every thread can have its own transmitter
    for i in 0..num_threads
    {
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, arguments.ipaddr, num_threads);
        });
    }


    //OUT VECTOR
    let mut out = vec![];
    drop(tx); //drop TX from this scope. This way, TX will only be in the other threads(not in the main thread)

    for p in rx 
    {
        out.push(p);
    }

    for v in  out
    {
    println!("{} is open", v);
    }
}