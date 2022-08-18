use std::{
    io,
    io::{ErrorKind, IoSliceMut},
    os::unix::prelude::AsRawFd,
};

const MESSAGE: &str = "Astra mortemque praestare gradatim";

fn main() -> io::Result<()> {
    let socket = std::net::UdpSocket::bind("127.0.0.1:3400")?;
    socket.connect("127.0.0.1:31337")?;
    set_timestamping_options(&socket)?;

    socket.send(MESSAGE.as_bytes())?;

    let send_timestamp = fetch_send_timestamp_help(&socket)?;

    let mut buf = vec![0; MESSAGE.len()];
    let (bytes_read, receive_timestamp) = recv(&socket, &mut buf)?;

    assert_eq!(bytes_read, MESSAGE.len());

    println!("timestamps:");
    println!("send:    {:?}", send_timestamp);
    println!("receive: {:?}", receive_timestamp);

    Ok(())
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Timestamp {
    seconds: i64,
    nanos: i64,
}

unsafe fn read_timestamp(ptr: *const u8) -> Timestamp {
    let ts: libc::timespec = std::ptr::read_unaligned(ptr as *const _);

    Timestamp {
        seconds: ts.tv_sec,
        nanos: ts.tv_nsec,
    }
}

/// Helper to handle C functions returning -1
fn cerr(t: libc::c_int) -> io::Result<libc::c_int> {
    match t {
        -1 => Err(io::Error::last_os_error()),
        _ => Ok(t),
    }
}

fn set_timestamping_options(udp_socket: &std::net::UdpSocket) -> io::Result<()> {
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

fn receive_message(
    socket: &std::net::UdpSocket,
    message_header: &mut libc::msghdr,
    flags: libc::c_int,
) -> io::Result<libc::c_int> {
    loop {
        match cerr(unsafe { libc::recvmsg(socket.as_raw_fd(), message_header, flags) } as _) {
            Err(e) if ErrorKind::Interrupted == e.kind() => {
                // retry when the recv was interrupted
                continue;
            }

            other => return other,
        }
    }
}

fn control_messages(message_header: &libc::msghdr) -> impl Iterator<Item = &libc::cmsghdr> {
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(message_header).as_ref() };

    std::iter::from_fn(move || match cmsg {
        None => None,
        Some(current) => {
            cmsg = unsafe { libc::CMSG_NXTHDR(message_header, current).as_ref() };

            Some(current)
        }
    })
}

fn control_message_space<T>() -> usize {
    // waiting for a release of libc to make this const
    (unsafe { libc::CMSG_SPACE((std::mem::size_of::<T>()) as _) }) as usize
}

fn recv(socket: &std::net::UdpSocket, buf: &mut [u8]) -> io::Result<(usize, Option<Timestamp>)> {
    let mut buf_slice = IoSliceMut::new(buf);

    let control_size = control_message_space::<[libc::timespec; 3]>();
    let mut control_buf = vec![0; control_size];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: (&mut buf_slice as *mut IoSliceMut).cast::<libc::iovec>(),
        msg_iovlen: 1,
        msg_flags: 0,
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
    };

    let bytes_read = receive_message(socket, &mut mhdr, 0)?;

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        eprintln!("truncated packet because it was larger than expected",);
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        eprintln!("truncated control messages");
    }

    // Loops through the control messages, but we should only get a single message
    let mut recv_ts = None;
    for msg in control_messages(&mhdr) {
        if let (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) = (msg.cmsg_level, msg.cmsg_type) {
            // Safety: SCM_TIMESTAMPING always has a timespec in the data, so this operation should be safe
            recv_ts = Some(unsafe { read_timestamp(libc::CMSG_DATA(msg)) });

            break;
        }
    }

    Ok((bytes_read as usize, recv_ts))
}

fn fetch_send_timestamp_help(socket: &std::net::UdpSocket) -> io::Result<Option<Timestamp>> {
    // we get back two control messages: one with the timestamp (just like a receive timestamp),
    // and one error message with no error reason. The payload for this second message is kind of
    // undocumented.
    //
    // section 2.1.1 of https://www.kernel.org/doc/Documentation/networking/timestamping.txt says that
    // a `sock_extended_err` is returned, but in practice we also see a socket address. The linux
    // kernel also has this https://github.com/torvalds/linux/blob/master/tools/testing/selftests/net/so_txtime.c#L153=
    let control_size = control_message_space::<[libc::timespec; 3]>()
        + control_message_space::<(libc::sock_extended_err, libc::sockaddr_storage)>();

    let mut control_buf = vec![0u8; control_size];
    let mut mhdr = libc::msghdr {
        msg_control: control_buf.as_mut_ptr().cast::<libc::c_void>(),
        msg_controllen: control_buf.len(),
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_flags: 0,
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
    };

    receive_message(socket, &mut mhdr, libc::MSG_ERRQUEUE)?;

    if mhdr.msg_flags & libc::MSG_TRUNC > 0 {
        eprintln!("truncated packet because it was larger than expected",);
    }

    if mhdr.msg_flags & libc::MSG_CTRUNC > 0 {
        eprintln!("truncated control messages");
    }

    let mut send_ts = None;
    for msg in control_messages(&mhdr) {
        match (msg.cmsg_level, msg.cmsg_type) {
            (libc::SOL_SOCKET, libc::SO_TIMESTAMPING) => {
                // Safety: SCM_TIMESTAMP always has a timespec in the data, so this operation should be safe
                send_ts = Some(unsafe { read_timestamp(libc::CMSG_DATA(msg)) });
            }
            (libc::SOL_IP, libc::IP_RECVERR) | (libc::SOL_IPV6, libc::IPV6_RECVERR) => {
                // this is part of how timestamps are reported.
                let error = unsafe {
                    let ptr: *const u8 = libc::CMSG_DATA(msg);
                    std::ptr::read_unaligned::<libc::sock_extended_err>(ptr as *const _)
                };

                // the timestamping does not set a message; if there is a message, that means
                // something else is wrong, and we want to know about it.
                if error.ee_errno as libc::c_int != libc::ENOMSG {
                    eprintln!("error message on the MSG_ERRQUEUE");
                }
            }
            _ => {
                eprintln!("unexpected message on the MSG_ERRQUEUE");
            }
        }
    }

    Ok(send_ts)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip() {
        let socket1 = std::net::UdpSocket::bind("127.0.0.1:3400").unwrap();
        let socket2 = std::net::UdpSocket::bind("127.0.0.1:3401").unwrap();

        set_timestamping_options(&socket1).unwrap();
        set_timestamping_options(&socket2).unwrap();

        socket1.connect("127.0.0.1:3401").unwrap();

        socket1.send(MESSAGE.as_bytes()).unwrap();

        let send_timestamp = fetch_send_timestamp_help(&socket1).unwrap();

        let mut buf = vec![0; MESSAGE.len()];
        let (bytes_read, receive_timestamp) = recv(&socket2, &mut buf).unwrap();

        assert_eq!(bytes_read, MESSAGE.len());

        assert!(send_timestamp < receive_timestamp);
    }
}
