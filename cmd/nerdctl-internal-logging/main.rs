#![no_main]

use libc;
use core::mem;
use core::ptr;
use anyhow::{anyhow, Result};
use errno::errno;

macro_rules! checked {
    ($e:expr) => (match $e {
        -1 => Err(anyhow!(errno())),
        n => Ok(n),
    })
}

#[no_mangle]
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    if let Err(e) = my_main(_argv) {
        eprintln!("Error: {}", e);
        return -1;
    }
    0
}

fn my_main(argv: *const *const u8) -> Result<String> {
    // std::fs::write(format!("{}/containers/{}/{}/log-config.json", path, ns, cid), r#"{"driver":"json-file"}"#)?;
  
    let mut data = String::new();

    unsafe {
        let path = *(argv.wrapping_add(2));
        let ns = libc::getenv("CONTAINER_NAMESPACE\0".as_ptr());
        let cid = libc::getenv("CONTAINER_ID\0".as_ptr());
        let mut filename = [0u8; libc::PATH_MAX as usize];
        checked!(libc::snprintf(filename.as_mut_ptr(), libc::PATH_MAX as usize, "%s/containers/%s/%s/%s-json.log\0".as_ptr(), path, ns, cid, cid))?;
        // libc::printf("ns=[%s], cid=[%s], filename=[%s]\0".as_ptr(), ns, cid, filename.as_ptr());

        let fd = checked!(libc::open(filename.as_ptr(), libc::O_WRONLY | libc::O_CREAT | libc::O_NONBLOCK))?;

        checked!(libc::fcntl(3, libc::F_SETFL, libc::fcntl(3, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::fcntl(4, libc::F_SETFL, libc::fcntl(4, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::close(5))?;

        let mut read_fds: libc::fd_set = mem::zeroed();
        let mut write_fds: libc::fd_set = mem::zeroed();
        loop {
            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(3, &mut read_fds);
            libc::FD_SET(4, &mut read_fds);

            checked!(libc::select(5, &mut read_fds, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()))?;

            if libc::FD_ISSET(3, &mut read_fds) {
                let line = read_and_encode_line(3, "stdout")?;
                data.push_str(&line);
            }

            if libc::FD_ISSET(4, &mut read_fds) {
                let line = read_and_encode_line(4, "stderr")?;
                data.push_str(&line);
            }

            if data.len() == 0 {
                libc::sleep(1);
                continue;
            }

            let length = data.len();
            let mut pos = 0;
            let mut buf = &mut data[pos..length];
            while buf.len() != 0 {
                libc::FD_ZERO(&mut write_fds);
                libc::FD_SET(fd, &mut write_fds);

                checked!(libc::select(fd+1, ptr::null_mut(), &mut write_fds, ptr::null_mut(), ptr::null_mut()))?;

                let n = checked!(libc::write(fd, buf.as_ptr() as *const _, buf.len()))?;
                pos += n as usize;
                buf = &mut data[pos..length];
            }

            data.clear()
        }
    };
}

fn read_and_encode_line(fd: i32, name: &str) -> Result<String> {
    const MAX_CONTAINER_LOG_LINE_SIZE: usize = 16384;
    let mut buffer = [0u8; MAX_CONTAINER_LOG_LINE_SIZE];
    let n = unsafe {
        match libc::read(fd, buffer.as_mut_ptr() as *mut _, MAX_CONTAINER_LOG_LINE_SIZE) {
            -1 => return Err(anyhow!(errno())),
            0 => return Err(anyhow!("fail to read from fd {}", fd)),
            n => n,
        }
    };
    let line = String::from_utf8_lossy(&buffer[0..n as usize]);
    let time = rfc3339_nanos()?;
    let mut s = String::new();
    s.push_str("{\"log\":\"");
    for c in line.chars() {
        match c {
            '"' => s.push_str("\\\""),
            '\\' => s.push_str("\\\\"),
            '\r' => s.push_str("\\r"),
            '\n' => s.push_str("\\n"),
            '\t' => s.push_str("\\t"),
            '\x0c' => s.push_str("\\u000c"),
            '\x08' => s.push_str("\\u0008"),
            '<' => s.push_str("\\u003c"),
            '\'' => s.push_str("\\u0027"),
            '\x1b' => s.push_str("\\u001b"),
            '\x00' => s.push_str("\\u0000"),
            _ => s.push(c),
        }
    }
    s.push_str("\",\"stream\":\"");
    s.push_str(name);
    s.push_str("\",\"time\":\"");
    s.push_str(&time);
    s.push_str("\"}\n");
    Ok(s)
}

fn rfc3339_nanos() -> Result<String> {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) < 0 {
            return Err(anyhow!(errno()))
        }
        let mut tm: libc::tm = mem::zeroed();
        if libc::gmtime_r(&ts.tv_sec, &mut tm).is_null() {
            return Err(anyhow!(errno()))
        }
        let time = format!("{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z", tm.tm_year+1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, ts.tv_nsec);
        Ok(time)
    }
}
