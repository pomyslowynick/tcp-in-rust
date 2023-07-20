use std::collections::HashMap;
use std::io;
use std::net::Ipv4Addr;

mod tcp;

#[derive(Eq, PartialEq, Clone, Debug, Hash)]
struct Quad {
    src: (Ipv4Addr, u16),
    dst: (Ipv4Addr, u16),
}

fn main() -> io::Result<()> {
    let mut connections: HashMap<Quad, tcp::Connection> = Default::default();
    let mut nic = tun_tap::Iface::without_packet_info("tun0", tun_tap::Mode::Tun)?;
    let mut buf = [0u8; 1504];
    loop {
        let nbytes = nic.recv(&mut buf[..])?;
        //let eth_flags = u16::from_be_bytes([buf[0], buf[1]]);
        //let eth_proto = u16::from_be_bytes([buf[2], buf[3]]);
        //if eth_proto != 0x0800 {
        //    // not ipv4
        //    continue;
        //}

        match etherparse::Ipv4HeaderSlice::from_slice(&buf[..nbytes]) {
            Ok(iphdr) => {
                let ip_source = iphdr.source_addr();
                let ip_dst = iphdr.destination_addr();

                if iphdr.protocol() != 0x06 {
                    // not TCP packet
                    continue;
                }
                match etherparse::TcpHeaderSlice::from_slice(&buf[iphdr.slice().len()..nbytes]) {
                    Ok(tcphdr) => {
                        use std::collections::hash_map::Entry;
                        let datai = iphdr.slice().len() + tcphdr.slice().len();
                        let tcp_source_port = tcphdr.source_port();
                        let tcp_dest_port = tcphdr.destination_port();
                        match connections.entry(Quad {
                            src: (ip_source, tcp_source_port),
                            dst: (ip_dst, tcp_dest_port),
                        }) {
                            Entry::Occupied(mut c) => {
                                c.get_mut().on_packet(
                                    &mut nic,
                                    iphdr,
                                    tcphdr,
                                    &buf[datai..nbytes],
                                )?;
                            }
                            Entry::Vacant(mut e) => {
                                if let Some(c) = tcp::Connection::accept(
                                    &mut nic,
                                    iphdr,
                                    tcphdr,
                                    &buf[datai..nbytes],
                                )? {
                                    e.insert(c);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!(
                            "Ignoring a weird tcp packet {:x?}, error {:?}",
                            &buf[iphdr.slice().len()..nbytes],
                            e
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "Ignoring a weird packet {:x?}, error {:?}",
                    &buf[4..nbytes],
                    e
                );
            }
        }
    }
    Ok(())
}
