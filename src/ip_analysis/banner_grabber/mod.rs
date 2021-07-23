use std::error;
use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;
pub fn resolve(address: &str) -> Result<SocketAddr, std::io::Error> {
    address.to_socket_addrs().map(|i| i.as_slice()[0])
}
pub fn grab_banner(address: &str) -> Result<String, Box<dyn error::Error>> {
    let address = resolve(address)?;
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(1))?;
    stream.set_read_timeout(Option::from(Duration::from_secs(1)))?;
    stream.set_write_timeout(Option::from(Duration::from_secs(1)))?;
    let mut buffer = Vec::new();
    let result = stream.read_to_end(&mut buffer);
    if result.is_ok() && !buffer.is_empty() {
        return Ok(String::from_utf8_lossy(&buffer).to_string());
    }
    let error = result.err().unwrap();
    if error.kind() != ErrorKind::WouldBlock {
        return Err(error.into());
    }
    stream.write_all("HEAD / HTTP/1.1\n\n".as_ref())?;
    stream.read_to_end(&mut buffer)?;
    Ok(String::from_utf8_lossy(&buffer).to_string())
}
