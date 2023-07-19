pub enum State {
    Closed,
    Listen,
    SynRcvd,
    Established,
}

impl Default for State {
    fn default() -> Self {
        // State::Closed
        State::Listen
    }
}

impl State {

    pub fn on_packet<'a>(&mut self, iph: etherparse::Ipv4HeaderSlice<'a>, tcph: etherparse::TcpHeaderSlice<'a>, data: &'a [u8]) {
        match *self {
            State::Closed => {
                return;
            }
            State::Listen => {
                if !tcph.sync() {
                    // didn't get a SYN packet
                    return; 
                }
                return;
            }
        }
        eprintln!("{}:{} -> {}:{} - bytes {}", iph.source_addr(), tcph.source_port(), iph.destination_addr(), tcph.destination_port(), data);
    }
}
