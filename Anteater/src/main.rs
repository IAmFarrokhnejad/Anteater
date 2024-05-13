use std::env;
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;

const MAX: u16 = 65535; //maximum sniffable port


struct Arguments
{
    flag: String,
    ipaddr: IpAddr,
    threads: u16,
}

//Implementation block
impl Arguments {
    fn new(args: &[String]) -> Result<Arguments, &'static str> {
        if args.len() < 2 {
            return Err("not enough arguments");
        } else if args.len() > 4 {
            return Err("too many arguments");
        }
        let f = args[1].clone();
        if let Ok(ipaddr) = IpAddr::from_str(&f) {
            return Ok(Arguments {
                flag: String::from(""),
                ipaddr,
                threads: 4,
            });
        } else {
            let flag = args[1].clone();
            if flag.contains("-h") || flag.contains("-help") && args.len() == 2 {
                println!(
                    "Usage: -j to select how many threads you want
                \n\r       -h or -help to show this help message"
                );
                return Err("help");
            } else if flag.contains("-h") || flag.contains("-help") {
                return Err("too many arguments");
            } else if flag.contains("-j") {
                let ipaddr = match IpAddr::from_str(&args[3]) {
                    Ok(s) => s,
                    Err(_) => return Err("not a valid IPADDR; must be IPv4 or IPv6"),
                };
                let threads = match args[2].parse::<u16>() {
                    Ok(s) => s,
                    Err(_) => return Err("failed to parse thread number"),
                };
                return Ok(Arguments {
                    threads,
                    flag,
                    ipaddr,
                });
            } else {
                return Err("invalid syntax");
            }
        }
    }
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
