#![no_main]

use libc;
use std::env;
use std::io;
use std::mem;
use std::ptr;
use std::fs;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;

macro_rules! checked {
    ($e:expr) => (match $e {
        -1 => Err(io::Error::last_os_error()),
        n => Ok(n),
    })
}

#[no_mangle]
pub extern "C" fn main(_argc: isize, _argv: *const *const u8) -> isize {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        return -1;
    }
    0
}

fn run() -> io::Result<()> {
    const MAX_SIZE : usize = 50 * 1024 * 1024;

    let path = env::args().nth(2).unwrap();
    let ns = env::var("CONTAINER_NAMESPACE").unwrap();
    let cid = env::var("CONTAINER_ID").unwrap();
    let filename = format!("{}/containers/{}/{}/{}-json.log", path, ns, cid, cid);
    let mut file = fs::OpenOptions::new().create(true).append(true).write(true).open(filename.clone())?;
    let mut filesize = file.metadata().unwrap().len() as usize;

    let mut data = String::new();

    // fs::write(format!("{}/containers/{}/{}/log-config.json", path, ns, cid), r#"{"driver":"json-file"}"#)?;

    unsafe {
        checked!(libc::fcntl(3, libc::F_SETFL, libc::fcntl(3, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::fcntl(4, libc::F_SETFL, libc::fcntl(4, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::close(5))?;

        let mut read_fds: libc::fd_set = mem::zeroed();
        loop {
            if filesize >= MAX_SIZE {
                drop(file);
                fs::rename(filename.clone(), filename.clone() + ".1")?;
                file = fs::OpenOptions::new().create(true).append(true).write(true).open(filename.clone())?;
                filesize = 0;
            }

            data.clear();

            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(3, &mut read_fds);
            libc::FD_SET(4, &mut read_fds);

            checked!(libc::select(5, &mut read_fds, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()))?;

            if libc::FD_ISSET(3, &mut read_fds) {
                copy_json_line("stdout",3,  &mut data)?;
            }

            if libc::FD_ISSET(4, &mut read_fds) {
                copy_json_line("stderr",4,  &mut data)?;
            }

            if data.len() == 0 {
                libc::sleep(1);
                continue;
            }

            filesize += data.len();
            file.write_all(data.as_bytes())?
        }
    };
}

fn copy_json_line( name: &str, fd: i32,writer: &mut String) -> io::Result<()> {
    const MAX_CONTAINER_LOG_LINE_SIZE: usize = 16384;
    let mut buffer = [0u8; MAX_CONTAINER_LOG_LINE_SIZE];
    let line = unsafe {
        match libc::read(fd, buffer.as_mut_ptr() as *mut _, MAX_CONTAINER_LOG_LINE_SIZE) {
            -1 => return Err(io::Error::last_os_error()),
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("fail to read from fd {}", fd))),
            n => std::str::from_utf8_unchecked(&buffer[0..n as usize]),
        }
    };
    writer.push_str("{\"log\":\"");
    for c in line.chars() {
        match c {
            '"' => writer.push_str("\\\""),
            '\\' => writer.push_str("\\\\"),
            '\r' => writer.push_str("\\r"),
            '\n' => writer.push_str("\\n"),
            '\t' => writer.push_str("\\t"),
            '\x0c' => writer.push_str("\\u000c"),
            '\x08' => writer.push_str("\\u0008"),
            '<' => writer.push_str("\\u003c"),
            '\'' => writer.push_str("\\u0027"),
            '\x1b' => writer.push_str("\\u001b"),
            '\x00' => writer.push_str("\\u0000"),
            _ => writer.push(c),
        }
    }
    writer.push_str("\",\"stream\":\"");
    writer.push_str(name);
    writer.push_str("\",\"time\":\"");
    write_rfc3339nano(writer)?;
    writer.push_str("\"}\n");
    Ok(())
}

#[inline(always)]
fn write_rfc3339nano(output: &mut String) -> io::Result<()> {
    unsafe {
        let mut ts: libc::timespec = mem::zeroed();
        if libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) < 0 {
            return Err(io::Error::last_os_error())
        }
        let mut tm: libc::tm = mem::zeroed();
        if libc::gmtime_r(&ts.tv_sec, &mut tm).is_null() {
            return Err(io::Error::last_os_error())
        }
        if let Err(e) = write!(output, "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec,ts.tv_nsec) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
        }
        Ok(())
    }
}
