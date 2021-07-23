use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::net::TcpStream;
use std::ops::Range;
use std::str;
#[derive(Debug)]
pub struct PortInfo {
    pub service_name: String,
    pub port: u16,
    pub protocal: String,
    pub open_frequency: f64,
    pub optional_comment: String,
}
impl fmt::Display for PortInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}/{} {} {}",
            self.service_name, self.port, self.protocal, self.open_frequency, self.optional_comment
        )
    }
}
pub fn get_services_tcp()->HashMap<u16, PortInfo>{
    let contents = fs::read_to_string("service-file").expect("Failed to read file");
    let contents_list = contents.split("\n").collect::<Vec<&str>>();
    let mut services = HashMap::new();
    for service in contents_list {
        let mut info = service.splitn(2, " ");
        let port = info.next().unwrap().split("\t").collect::<Vec<&str>>();
        let message = match info.next() {
            Some(message) => message,
            None => "None",
        };
        let port_desc = port[1].split("/").collect::<Vec<&str>>();
        if port_desc[1].to_owned() == "tcp" {
            let port_info = PortInfo {
                service_name: port[0].to_owned(),
                port: port_desc[0].to_owned().parse().unwrap(),
                protocal: port_desc[1].to_owned(),
                open_frequency: port[2].to_owned().parse().unwrap(),
                optional_comment: message.to_owned(),
            };
            services.insert(port_desc[0].to_owned().parse().unwrap(), port_info);
        }
    }
    services
}
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
