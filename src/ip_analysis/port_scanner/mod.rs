use std::fmt;
use std::net::TcpStream;
use std::ops::Range;
#[derive(Debug)]
pub struct Address {
    pub ip: String,
    pub port: u16,
}
impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({}:{})", self.ip, self.port)
    }
}
pub fn scan_port_addrs(addresses: Vec<String>, ports: Vec<u16>) -> Vec<Address> {
    let mut opened: Vec<Address> = Vec::new();
    for address in addresses {
        for port in &ports {
            let addr = format!("{}:{}", address, port);
            match TcpStream::connect(addr) {
                Ok(_) => {
                    let open_addr = Address {
                        ip: address.clone(),
                        port: port.clone(),
                    };
                    opened.push(open_addr);
                }
                Err(_) => {}
            }
        }
    }
    opened
}
pub fn scan_port_addrs_range(addresses: Vec<String>, ports: Range<u16>) -> Vec<Address> {
    scan_port_addrs(addresses, ports.collect())
}
