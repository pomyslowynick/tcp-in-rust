use std::io;

pub enum State {
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    TimeWait,
}

impl State {
    fn is_synchronized(&self) -> bool {
        match *self {
            State::SynRcvd => false,
            State::Established | State::FinWait1 | State::FinWait2 | State::Closing | State::TimeWait => true,
        }
    }
}
pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    iphr: etherparse::Ipv4Header,
    tcp: etherparse::TcpHeader,
}

///  Send Sequence Space
///
///  ```
///            1         2          3          4
///       ----------|----------|----------|----------
///              SND.UNA    SND.NXT    SND.UNA
///                                   +SND.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers of unacknowledged data
/// 3 - sequence numbers allowed for new data transmission
/// 4 - future sequence numbers which are not yet allowed
/// ```

struct SendSequenceSpace {
    /// send unacknowledged
    una: u32,
    /// send next
    nxt: u32,
    /// send window
    wnd: u16,
    /// send urgent pointer
    up: bool,
    /// segment sequence number used for last window update
    wl1: usize,
    /// segment acknowledgment number used for last window update
    wl2: usize,
    /// initial send sequence number
    iss: u32,
}

///  Receive Sequence Space
/// ```
///                1          2          3
///            ----------|----------|----------
///                   RCV.NXT    RCV.NXT
///                             +RCV.WND
///
/// 1 - old sequence numbers which have been acknowledged
/// 2 - sequence numbers allowed for new reception
/// 3 - future sequence numbers which are not yet allowed
/// ```
struct ReceiveSequenceSpace {
    /// receive next
    nxt: u32,
    /// receive window
    wnd: u16,
    /// receive urgent pointer
    up: bool,
    /// initial receive sequence number
    irs: u32,
}

impl Connection {
    pub fn accept<'a>(
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<Option<Self>> {
        if !tcph.syn() {
            // didn't get a SYN packet
            return Ok(None);
        }

        let iss = 0;
        let wnd = 10;
        let mut c = Connection {
            state: State::SynRcvd,
            // Sender state
            recv: ReceiveSequenceSpace {
                // keep track of sender info, initial sequence number sent by the sender
                // Initial Receive Sequence Number
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
            },
            // Our side state
            send: SendSequenceSpace {
                // decide on stuff we're sending them
                iss,
                una: iss,
                nxt: iss,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            tcp: etherparse::TcpHeader::new(
                tcph.destination_port(),
                tcph.source_port(),
                iss,
                wnd
            ),
            iphr: etherparse::Ipv4Header::new(0, 64, 6, iph.destination(), iph.source()),
        };

        c.tcp.syn = true;
        c.tcp.ack = true;

        // Why do we write an empty struct to the nic? I don't remember what that part was supposed
        // to do. I must have omitted some part.
        // Oh, I think we are using the Connection write at this point, this is implemented below.
        // So this is a nic and an empty payload, we are sending an ACK response
        c.write(nic, &[])?;
        return Ok(Some(c));
    }

    fn write(&mut self, nic: &mut tun_tap::Iface, payload: &[u8]) -> io::Result<usize> {
        // We are responding, so the sqn we include in the packet is the next available one,
        // send.nxt
        let mut buf = [0u8; 1500];
        self.tcp.sequence_number = self.send.nxt;
        self.tcp.acknowledgment_number = self.recv.nxt;
        // This is done by the kernel, we don't need to calculate the checksum
        // let payload = [0u8; 0];
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &payload).expect("failed to compute checksum");

        // not sure about this min use here, shouldn't those headers be written to it? Maybe it
        // only happens in on_packet
        let size = std::cmp::min(buf.len(), self.tcp.header_len() as usize + self.iphr.header_len() as usize + payload.len());

        // historically TCP datagram doesn't have information on the length, IP packet does
        self.iphr.set_payload_len(size);
        // This is some Rust magic from Jon, where the slice pointer for buf, assigned to
        // unwritten moves furter as we write to buf. So the final returned length is
        // however much space is left in the buf, after we wrote to it.
        use std::io::Write;
        let mut unwritten = &mut buf[..];
        self.iphr.write(&mut unwritten);
        self.tcp.write(&mut unwritten);
        let payload_bytes = unwritten.write(payload)?;
        let unwritten = unwritten.len();

        // We add teh payload bytes because we are only counting the sent data when incrementing
        // the sequence numbers
        self.send.nxt.wrapping_add(payload_bytes as u32);
        // If it's a syn we will add 1? not sure why
        if self.tcp.syn {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.syn = false;
        }
        // Same with FIN need to look into it
        if self.tcp.fin {
            self.send.nxt = self.send.nxt.wrapping_add(1);
            self.tcp.fin = false;
        }
        nic.send(&buf[..buf.len() - unwritten])?;
        Ok(payload_bytes)
    }
    
    pub fn send_rst(&mut self, nic: &mut tun_tap::Iface) -> io::Result<()> {
        self.tcp.rst = true;
        self.tcp.sequence_number = 0;
        self.tcp.acknowledgment_number = 0;
        self.iphr.set_payload_len(self.tcp.header_len() as usize);
        nic.send(&[])?;
        return Ok(());
    }
    
    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // we copy the received seqn
        // why do we need to?
        // think it's for code readability
        // compiler will subtitute it anyway
        let seqn = tcph.sequence_number();
        let mut slen = data.len() as u32;
        // I'll be honest, I don't understand why the length
        // increases if the flags were set
        //      I think I get it, it's because slen is used
        //      to keep track of the ack number, and it will
        //      be incremented on each of the flags
        if tcph.fin() {
            slen += 1;
        };
        if tcph.syn() {
            slen += 1;
        };
        // the window end, nxt + wnd
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        
        // I think that we don't have to worry about the scenarios below
        // yet, it's mostly for future scenarios with win == 0
        // or when there's no SYN or FIN set
        // Maybe that's why Jon sets the length here?
        //
        // Jon says that getting through this check means we have acked
        // at least one byte. This must be some property of comparing with
        // nxt, but I am still not convinced.
        if slen == 0 {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                return Ok(());
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else if !is_between_wrapped(
                self.recv.nxt.wrapping_sub(1),
                seqn,
                wend,
            ) {
                return Ok(());
            }
        }
        // We add the length of the payload to the nxt delimiter
        self.recv.nxt = seqn.wrapping_add(slen);

        if !tcph.ack() {
            return Ok(());
        }
        // acceptable ack check
        let ackn = tcph.acknowledgment_number();

        if let State::SynRcvd = self.state {
            if !is_between_wrapped(self.send.una.wrapping_sub(1), ackn, self.send.nxt.wrapping_add(1)) {
                self.state = State::Established;
            } else {
                // TODO: RST
            }
        }

        if let State::Established = self.state {
            if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
                return Ok(());
            }
            self.send.una = ackn;
            assert!(data.is_empty());

            self.tcp.fin = true;
            self.write(nic, &[])?;
            self.state = State::FinWait1;
        }

        if let State::FinWait1 = self.state {
            if self.send.una == self.send.iss + 2 {
            // our Fin has beeen acked
            self.state = State::FinWait2;
        }
                // I guess this is true because data is empty (we didn't receive
                // anything) and it's a FIN packet
                // Also, Jon keeps saying that we acked something, so I guess the code
                // above is making sure that we did receive an ACK?
                //      must have ACKed our FIN, since we detected at least on acked byte 
                //      and we have only sent on byte (the FIN)
                self.state = State::FinWait2;
            }

        if tcph.fin() {
            match self.state {
                State::FinWait2 => {
                    // we're done with the connection
                    self.write(nic, &[])?;
                    self.state = State::TimeWait;
                },
                _ => unimplemented!(),
            }
        }

        if let State::FinWait2 = self.state {
            if !tcph.fin() || !data.is_empty() {
                unimplemented!();
            }

            self.state = State::FinWait2;
            // must have ACKed our FIN, since we detected at least one acked byte 
            // and we have only sent one byte (the FIN)
            self.tcp.fin = false;
            self.write(nic, &[])?;
            self.state = State::TimeWait;
        }
        return Ok(());
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(&x) {
        Ordering::Equal => return false,
        Ordering::Less => {
            //
            // |----------S----X---------------|
            //
            // X is between S and E (S < X < E) iff !(S <= E <= X)
            if end <= x && start <= end {
                return false;
            }
        }
        Ordering::Greater => {
            if end <= x && start < end {
                return false;
            }
        }
    }
    true
}
