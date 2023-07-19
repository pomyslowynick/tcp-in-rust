SHELL = /usr/bin/bash

all:
	cargo b 
	sudo setcap cap_net_admin=eip ./target/debug/trust
	#PID := $(./target/debug/trust &)
	./target/debug/trust & echo $$! > trust.PID
	sleep 2
	sudo ip a add dev tun0 192.168.0.1/24
	sudo ip link set dev tun0 up
	trap "kill $$(cat trust.PID)" INT TERM
	tail --pid=$$(cat trust.PID) -f
