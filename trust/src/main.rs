use std::io;
use std::net::Ipv4Addr;
use std::collections::HashMap;

mod tcp;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::State> = Default::default();
    let nic = tun_tap::Iface::new("tun0", tun_tap::Mode::Tun).expect("failed to cr");
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf [..])?;
        let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        if eth_proto != 0x0800 {
            // not ipv4
            continue;
        }

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[4..nbytes]) {
            Ok(iphdr) => {
                let ip_source = iphdr.source_addr();
                let ip_dst = iphdr.destination_addr();

                if iphdr.protocol() != 0x06 {
                    // not TCP packet
                    continue
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[4+iphdr.slice().len()..nbytes]) {
                    Ok(tcphdr) => {
                        let datai = 4 + iphdr.slice().len() + tcphdr.slice().len();
                        let tcp_source_port = tcphdr.source_port();
                        let tcp_dest_port = tcphdr.destination_port();
                        connections.entry(Quad {
                            src: (ip_source, tcp_source_port),
                            dst: (ip_dst, tcp_dest_port),
                        }).or_default().on_packet(iphdr, tcphdr, &buf[datai..nbytes])

                    },
                    Err(e) => {
                        eprintln!("Ignoring a weird tcp packet {:x?}, error {:?}", &buf[4+iphdr.slice().len()..nbytes], e);
                    }

                }
            },
            Err(e) => {
                eprintln!("Ignoring a weird packet {:x?}, error {:?}", &buf[4..nbytes], e);
            }
        }
    }
    Ok(())
}
