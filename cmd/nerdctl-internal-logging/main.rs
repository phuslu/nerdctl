#![no_main]

use libc;
use std::{
    env,
    io::{self, Write},
    mem::{self, MaybeUninit},
    fmt::Write as FmtWrite,
    ptr,
    fs,
};

const MAX_FILE_SIZE: usize = 50 * 1024 * 1024;  // 50MB
const MAX_LOG_LINE_SIZE: usize = 16 * 1024;     // 16KB
const SELECT_TIMEOUT_SECS: i64 = 60;

macro_rules! checked {
    ($e:expr) => {
        match $e {
            -1 => Err(io::Error::last_os_error()),
            n => Ok(n),
        }
    };
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
    let path = env::args().nth(2).ok_or_else(||
        io::Error::new(io::ErrorKind::InvalidInput, "Missing path argument"))?;
    let ns = env::var("CONTAINER_NAMESPACE").map_err(|e|
        io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    let cid = env::var("CONTAINER_ID").map_err(|e|
        io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;

    let filename = format!("{}/containers/{}/{}/{}-json.log", path, ns, cid, cid);
    let mut file = fs::OpenOptions::new().create(true).append(true).write(true).open(&filename)?;
    let mut filesize = file.metadata()?.len() as usize;

    unsafe {
        checked!(libc::fcntl(3, libc::F_SETFL, libc::fcntl(3, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::fcntl(4, libc::F_SETFL, libc::fcntl(4, libc::F_GETFL) | libc::O_NONBLOCK))?;
        checked!(libc::close(5))?;

        let mut read_fds: libc::fd_set = mem::zeroed();
        let mut timeout = libc::timeval {
            tv_sec: SELECT_TIMEOUT_SECS,
            tv_usec: 0,
        };

        let mut buffer = [0u8; MAX_LOG_LINE_SIZE];
        let mut output = String::with_capacity(MAX_LOG_LINE_SIZE * 2);

        loop {
            if filesize >= MAX_FILE_SIZE {
                drop(file);
                fs::rename(&filename, format!("{}.1", filename))?;
                file = fs::OpenOptions::new().create(true).append(true).write(true).open(&filename)?;
                filesize = 0;
            }

            libc::FD_ZERO(&mut read_fds);
            libc::FD_SET(3, &mut read_fds);
            libc::FD_SET(4, &mut read_fds);

            timeout.tv_sec = SELECT_TIMEOUT_SECS;
            checked!(libc::select(5, &mut read_fds, ptr::null_mut(), ptr::null_mut(), &mut timeout))?;

            if libc::FD_ISSET(3, &mut read_fds) {
                output.clear();
                copy_json_line("stdout", 3, &mut buffer, &mut output)?;
                if !output.is_empty() {
                    file.write_all(output.as_bytes())?;
                    filesize += output.len();
                }
            }

            if libc::FD_ISSET(4, &mut read_fds) {
                output.clear();
                copy_json_line("stderr", 4, &mut buffer, &mut output)?;
                if !output.is_empty() {
                    file.write_all(output.as_bytes())?;
                    filesize += output.len();
                }
            }
        }
    }
}

fn copy_json_line(name: &str, fd: i32, buffer: &mut [u8], output: &mut String) -> io::Result<()> {
    let n = unsafe {
        match libc::read(fd, buffer.as_mut_ptr() as *mut _, buffer.len()) {
            -1 => return Err(io::Error::last_os_error()),
            0 => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, format!("EOF on fd {}", fd))),
            n => n as usize,
        }
    };

    output.reserve(n * 2 + 100);
    output.push_str("{\"log\":\"");

    let input = unsafe { std::str::from_utf8_unchecked(&buffer[0..n]) };
    for c in input.chars() {
        match c {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\r' => output.push_str("\\r"),
            '\n' => output.push_str("\\n"),
            '\t' => output.push_str("\\t"),
            '\x0c' => output.push_str("\\u000c"),
            '\x08' => output.push_str("\\u0008"),
            '<' => output.push_str("\\u003c"),
            '\'' => output.push_str("\\u0027"),
            '\x1b' => output.push_str("\\u001b"),
            '\x00' => output.push_str("\\u0000"),
            _ => output.push(c),
        }
    }

    output.push_str("\",\"stream\":\"");
    output.push_str(name);
    output.push_str("\",\"time\":\"");
    write_rfc3339nano(output)?;
    output.push_str("\"}\n");

    Ok(())
}

#[inline(always)]
fn write_rfc3339nano(output: &mut String) -> io::Result<()> {
    unsafe {
        let mut ts: MaybeUninit<libc::timespec> = MaybeUninit::uninit();
        if libc::clock_gettime(libc::CLOCK_REALTIME, ts.as_mut_ptr()) < 0 {
            return Err(io::Error::last_os_error());
        }
        let ts = ts.assume_init();

        let mut tm: MaybeUninit<libc::tm> = MaybeUninit::uninit();
        if libc::gmtime_r(&ts.tv_sec, tm.as_mut_ptr()).is_null() {
            return Err(io::Error::last_os_error());
        }
        let tm = tm.assume_init();

        output.reserve(32);
        write!(output,
            "{}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}Z",
            tm.tm_year + 1900,
            tm.tm_mon + 1,
            tm.tm_mday,
            tm.tm_hour,
            tm.tm_min,
            tm.tm_sec,
            ts.tv_nsec
        ).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))
    }
}
