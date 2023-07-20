use std::io;

pub enum State {
    //Listen,
    SynRcvd,
    Established,
}

pub struct Connection {
    state: State,
    send: SendSequenceSpace,
    recv: ReceiveSequenceSpace,
    iphr: etherparse::Ipv4Header,
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
        let mut buf = [0u8; 1500];
        if !tcph.syn() {
            // didn't get a SYN packet
            return Ok(None);
        }

        let iss = 0;
        let mut c = Connection {
            state: State::SynRcvd,
            recv: ReceiveSequenceSpace {
                // keep track of sender info
                irs: tcph.sequence_number(),
                nxt: tcph.sequence_number() + 1,
                wnd: tcph.window_size(),
                up: false,
                //self.recv.up: tcph.urg();
            },
            send: SendSequenceSpace {
                // decide on stuff we're sending them
                iss,
                una: iss,
                nxt: iss + 1,
                wnd: 10,
                up: false,
                wl1: 0,
                wl2: 0,
            },
            iphr: etherparse::Ipv4Header::new(0, 64, 6, iph.destination(), iph.source()),
        };

        let mut syn_ack = etherparse::TcpHeader::new(
            tcph.destination_port(),
            tcph.source_port(),
            c.send.iss,
            c.send.wnd,
        );
        c.iphr.set_payload_len(syn_ack.header_len() as usize + 0);
        syn_ack.acknowledgment_number = c.recv.nxt;
        syn_ack.syn = true;
        syn_ack.ack = true;

        // This is done by the kernel, we don't need to calculate the checksum
        // let payload = [0u8; 0];
        // syn_ack.checksum = syn_ack.calc_checksum_ipv4(&ip, &payload).expect("failed to compute checksum");

        // This is some Rust magic from Jon, where the slice pointer for buf, assigned to
        // unwritten moves furter as we write to buf. So the final returned length is
        // however much space is left in the buf, after we wrote to it.
        //
        eprintln!("received ip packet is: {:02x?}", iph);
        eprintln!("received tcp packet is: {:02x?}", tcph);

        let mut unwritten = {
            let mut unwritten = &mut buf[..];
            c.iphr.write(&mut unwritten);
            syn_ack.write(&mut unwritten);
            unwritten.len()
        };
        nic.send(&buf[..buf.len() - unwritten])?;
        eprintln!(
            "packet we want to send is {:02x?}",
            &buf[..buf.len() - unwritten]
        );
        return Ok(Some(c));
    }

    pub fn on_packet<'a>(
        &mut self,
        nic: &mut tun_tap::Iface,
        iph: etherparse::Ipv4HeaderSlice<'a>,
        tcph: etherparse::TcpHeaderSlice<'a>,
        data: &'a [u8],
    ) -> io::Result<()> {
        // acceptable ack check
        let ackn = tcph.acknowledgment_number();
        if !is_between_wrapped(self.send.una, ackn, self.send.nxt.wrapping_add(1)) {
            return Ok(());
        }

        let seqn = tcph.sequence_number();
        let wend = self.recv.nxt.wrapping_add(self.recv.wnd as u32);
        if data.len() == 0 && !tcph.ack() && !tcph.fin() {
            // zero-length segment has separate rules for acceptance
            if self.recv.wnd == 0 {
                if seqn != self.recv.nxt {
                    return Ok(());
                }
            } else {
                if !is_between_wrapped(self.recv.nxt.wrapping_sub(1), seqn, wend) {
                    return Ok(());
                }
            }
        } else {
            if self.recv.wnd == 0 {
                return Ok(());
            } else {
                if !is_between_wrapped(
                    self.recv.nxt.wrapping_sub(1),
                    seqn,
                    wend && self.recv.nxt.wrapping_sub(1),
                    seqn + data.len() as u32 - 1,
                    wend,
                ) {
                    return Ok(());
                }
            }
        }
        match self.state {
            State::SynRcvd => {
                // wrapping add is used, because we tolerate overflow in TCP
            }
            State::Established => {
                unimplemented!();
            }
        }
    }
}

fn is_between_wrapped(start: u32, x: u32, end: u32) -> bool {
    use std::cmp::Ordering;
    match start.cmp(x) {
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
