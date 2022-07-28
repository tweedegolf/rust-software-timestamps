# Software send and receive timestamps using libc primitives in rust

A runnable example of send and receive software (kernel) timestamping.

Please let us know if there are ways to reduce usage of unsafe, or missed edge cases!

## Running

First start the UDP echo server

```shell
> python3 echo-server.py
Listening on 0.0.0.0:31337
```

Then, in a different shell, run 

```
> cargo run
timestamps:
send:    Some(Timestamp { seconds: 1658995837, nanos: 696817305 })
receive: Some(Timestamp { seconds: 1658995837, nanos: 696932172 })
```

## Braindump

A quick, somewhat coherent writeup of what we learned.

The rust standard library does not provide the tools for software timestamps. Instead, we need to break down its abstractions and use libc for getting to the timestamps.

On unix systems, a `std::net::UdpSocket` can be unwrapped to give a `RawFd`, which is a 32-bit unix file descriptor. It can be used as the `fd` argument in many libc functions.

Software timestamping needs to be enabled on a per-socket basis. `setsockopt` sets socket options. We want 4 bits to be set for our demo:

- `SOF_TIMESTAMPING_SOFTWARE` reports software timestamps
- `SOF_TIMESTAMPING_RX_SOFTWARE` records receive timestamps
- `SOF_TIMESTAMPING_TX_SOFTWARE` records send (transmit) timestamps
- `SOF_TIMESTAMPING_OPT_TSONLY` convenient for tx timestamps, see below 

```rust
fn set_timestamping_options(udp_socket: &std::net::UdpSocket) -> io::Result<()> {
    use std::os::unix::prelude::AsRawFd,

    let fd = udp_socket.as_raw_fd();

    const SOF_TIMESTAMPING_OPT_TSONLY: u32 = 1 << 11;

    // our options:
    //  - we want software timestamps to be reported,
    //  - we want both send and receive software timestamps
    let bits = libc::SOF_TIMESTAMPING_SOFTWARE
        | libc::SOF_TIMESTAMPING_RX_SOFTWARE
        | libc::SOF_TIMESTAMPING_TX_SOFTWARE
        | SOF_TIMESTAMPING_OPT_TSONLY;

    unsafe {
        cerr(libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_TIMESTAMPING,
            &bits as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ))?
    };

    Ok(())
}
```

With the socket configured, we can get to sending and receiving.


## Receive timestamps

Receive timestamps are the easier of the two, so we'll look at them first.

When receiving a message, the timestamp is attached as a control message. Control messages serve many purposes, we are looking for a specific message with level `SOL_SOCKET` and type `SO_TIMESTAMPING`. This message contains three `libc::timespec` values, but only the first one is relevant for software timestamping.

```rust
// Loops through the control messages, but we should only get a single message
let mut recv_ts = None;
for msg in control_messages(&mhdr) {
    if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) = (msg.cmsg_level, msg.cmsg_type) {
        // Safety: SCM_TIMESTAMPING always has a timespec in the data, so this operation should be safe
        recv_ts = Some(unsafe { read_timestamp(libc::CMSG_DATA(msg)) });

        break;
    }
}
```

## Send timestamps

Send timestamps are a bit trickier. After sending the message, we must receive on the same socket but with the `libc::MSG_ERRQUEUE` flag. 

```
receive_message(socket, &mut mhdr, libc::MSG_ERRQUEUE)?;
```

The message we receive is empty (does not have a body) because we set `SOF_TIMESTAMPING_OPT_TSONLY`. If we don't set this flag, we get the full ethernet frame of the message that was sent. Not sending that body is a bit more efficient, and means we don't have to deal with it at all.

The actual timestamp is again sent as a control message. We iterate through these messages (though there should be only 2, in a specific order) and extract the timestamp. 

A note about the size of the control message buffer: Based on the documentation, we'd expect the timestamp control message to contain three `libc::timespec`s, and an error control message that contains a `libc::sock_extended_err`. But in practice the size of the second control message is larger. It seems to also store a socket address. We cannot find the details in any documentation. If you know what's happening here, let us know!  

