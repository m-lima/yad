#![deny(warnings, missing_docs, rust_2018_idioms, clippy::pedantic)]
#![cfg(target_family = "unix")]

//! Yet Another Daemonizer is a daemonizing crate to easily, simply, and **correctly** create legacy
//! daemons.
//!
//! This crate focuses on manually creating a background process which is not managed by a
//! supervisor such as systemd or launchd. It strives to follow all the best practices
//! to correctly daemonize a process.
//!
//! # Example
//! ```no_run
//! use yad::options::Stdio;
//!
//! match yad::with_options()
//!     .stdin(Stdio::Null)
//!     .stderr(Stdio::Null)
//!     .stdout(Stdio::output("/var/log/daemon.log"))
//!     .daemonize()
//! {
//!     Ok(_) => println!("I'm a daemon"),
//!     Err(err) => eprintln!("Failed to launch daemon: {}", err),
//! }
//! ```
//!
//! # References
//! * [Man page for daemon()](https://man7.org/linux/man-pages/man7/daemon.7.html)
//! * [Reference project in C](https://chaoticlab.io/c/c++/unix/2018/10/01/daemonize.html)

pub mod options;

type InvocationResult<T = ()> = Result<T, Error>;
type DaemonResult<T = ()> = Result<T, (DaemonError, nix::Error)>;

/// Errors that can happen while daemonizing.
///
/// These errors are received in the invoking process, i.e. the proccess that called
/// [`daemonize()`](fn.daemonize.html).
#[derive(thiserror::Error, Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Daemon pid file already exists
    #[error("Daemon pid file already exists")]
    DaemonAlreadyRunning,

    /// Failed to close file descriptors
    #[error("Failed to close file descriptors: {0}")]
    CloseDescriptors(nix::Error),

    /// Failed to fetch open file descriptors
    #[error("Failed to fetch open file descriptors: {0}")]
    ListOpenDescriptors(nix::Error),

    /// Failed to reset signal handlers
    #[error("Failed to reset signal handlers: {0}")]
    ResetSignals(nix::Error),

    /// Failed to block signals
    #[error("Failed to block signals: {0}")]
    BlockSignals(nix::Error),

    /// Failed to create status reporting pipe
    #[error("Failed to create status reporting pipe: {0}")]
    CreatePipe(nix::Error),

    /// Failed to fork daemon process
    #[error("Failed to fork daemon process: {0}")]
    Fork(nix::Error),

    /// Failed to receive daemon status report
    #[error("Failed to receive daemon status report: {0}")]
    ReadStatus(nix::Error),

    /// Failed to start daemon after forking with a wrapped [`DaemonError`](enum.DaemonError.html)
    #[error("Daemon failed to initialize: {error}: {cause}")]
    Daemon {
        /// The wrapped error sent by the forked process
        error: DaemonError,
        /// The raw underlying error
        cause: nix::Error,
    },

    /// Failure after daemonizing while initializing
    #[error("Daemon failed to initialize: {code}")]
    Initialization {
        /// The received numeric representation of the error
        code: ErrorCode,
    },
}

impl Error {
    fn daemon(error: DaemonError, cause: nix::Error) -> Self {
        Self::Daemon { error, cause }
    }
}

/// An error that occurs during initialization that can be represented as an `i32` and sent through
/// the pipe back to the invoking process error handling.
///
/// The is the expected error returned from [`daemonize_with_init()`](fn.daemonize_with_init.html).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct ErrorCode(pub i32);

impl<I: Into<i32>> From<I> for ErrorCode {
    fn from(code: I) -> Self {
        Self(code.into())
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// Wrapped errors that can happen after the daemon has forked.
///
/// The error is reported by another process through pipes and received by the invoking process,
/// i.e. the process that called [`daemonize()`](fn.daemonize.html), will handle the error.
///
/// The forked process will be guaranteed to be terminated and the invoking process will own all
/// resources.
///
/// # See also
/// [`Error`](enum.Error.html)
#[derive(thiserror::Error, yad_derive::FromNum, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum DaemonError {
    /// Failure detaching from session
    #[error("Failed to detach from session")]
    Setsid = 1,

    /// Failure during the second call to `fork()`
    #[error("Failed to double fork daemon")]
    Fork = 2,

    /// Failure changing root directory
    #[error("Failed to change root directory")]
    ChangeRoot = 3,

    /// Failure setting UID
    #[error("Failed to set user")]
    SetUser = 4,

    /// Failure setting GID
    #[error("Failed to set group")]
    SetGroup = 5,

    /// Failure unblocking the signals
    #[error("Failed to unblock signals")]
    UnblockSignals = 6,

    /// Failure closing file descriptors
    #[error("Failed to close file descriptors")]
    CloseDescriptors = 7,

    /// Failure listing open file descriptors
    #[error("Failed to fetch open file descriptors")]
    ListOpenDescriptors = 8,

    /// Failure resetting signal handlers
    #[error("Failed to reset signal handlers")]
    ResetSignals = 9,

    /// Failure redirecting STDIN
    #[error("Failed to redirect stdin")]
    RedirectStdin = 10,

    /// Failure redirecting STDOUT
    #[error("Failed to redirect stdout")]
    RedirectStdout = 11,

    /// Failure redirecting STDERR
    #[error("Failed to redirect stderr")]
    RedirectStderr = 12,

    /// Failure after daemonizing while initializing
    #[error("Failed initialize daemon after forking")]
    Initialization = 13,
}

#[derive(Debug)]
enum ForkResult {
    Invoker(Pipe, nix::unistd::Pid),
    Daemon(Pipe),
}

/// Starts the daemon with default options.
///
/// When this method returns, if it is a failure, it is guaranteed to be running on the
/// original process. If it is a success, it is guaranteed to be running as a daemon.
///
/// # Example
/// ```no_run
/// match yad::daemonize() {
///     Ok(_) => println!("I'm a daemon"),
///     Err(err) => eprintln!("Failed to launch daemon: {}", err),
/// }
/// ```
///
/// # Errors
/// If the daemonizing operation fails.
///
/// The invoking process, i.e. the process that called [`daemonize()`](fn.daemonize.html),
/// will handle the error. The forked process will be guaranteed to be terminated and the invoking
/// process will own all resources.
///
/// # See also
/// [`with_options()`](fn.with_options.html)
pub fn daemonize() -> InvocationResult {
    daemonize_inner(options::Options::new(), || Ok(()))
}

/// Starts the daemon with default options executing `initialization` after forking the process.
///
/// When this method returns, if it is a failure, it is guaranteed to be running on the
/// original process. If it is a success, it is guaranteed to be running as a daemon.
///
/// If the initialization fails, the error will be converted to an `i32` representation and sent
/// though the pipe back to the invoking process. The forked daemon will unwind its initialization
/// stack, and terminate without unwind any further. The invoking process will own all shared
/// resources.
///
/// Therefore, when this method returns, if it is a failure, it is guaranteed to be running on the
/// original process. If it is a success, it is guaranteed to be running as a daemon.
///
/// # Example
/// ```no_run
/// #[repr(u8)]
/// enum Error {
///     Read = 1,
///     Write = 2,
/// }
///
/// impl From<Error> for i32 {
///     fn from(e: Error) -> Self {
///         e as i32
///     }
/// }
///
/// match yad::daemonize_with_init(|| {
///     let file = std::fs::File::open("a_file").map_err(|_| Error::Read)?;
///     std::fs::write("another_file", b"some_content").map_err(|_| Error::Write)?;
///     Ok(file)
/// }) {
///     Ok(file) => println!("I'm a daemon with {file:?}"),
///     Err(err) => eprintln!("Failed to launch daemon: {}", err),
/// }
/// ```
///
/// # Errors
/// If the daemonizing operation fails or if the initialization fails.
///
/// The invoking process, i.e. the process that called [`daemonize()`](fn.daemonize.html),
/// will handle the error. The forked process will be guaranteed to be terminated and the invoking
/// process will own all resources.
///
/// Any resources acquired during `initialization` execution will be owned just by the forked
/// process and will be unwound and dropped upon error.
///
/// # See also
/// [`with_options()`](fn.with_options.html)
pub fn daemonize_with_init<F, R>(initialization: F) -> InvocationResult<R>
where
    F: FnOnce() -> Result<R, ErrorCode>,
{
    daemonize_inner(options::Options::new(), initialization)
}

/// Starts the daemon with the given options.
///
/// # Example
/// ```no_run
/// use yad::options::Stdio;
///
/// match yad::with_options()
///     .stdin(Stdio::Null)
///     .stderr(Stdio::Null)
///     .stdout(Stdio::output("/var/log/daemon.log"))
///     .daemonize()
/// {
///     Ok(_) => println!("I'm a daemon"),
///     Err(err) => eprintln!("Failed to launch daemon: {}", err),
/// }
/// ```
///
/// # See also
/// [`daemonize()`](fn.daemonize.html)
#[must_use]
pub fn with_options() -> options::Options {
    options::Options::new()
}

fn daemonize_inner<F, R>(options: options::Options, initialization: F) -> InvocationResult<R>
where
    F: FnOnce() -> Result<R, ErrorCode>,
{
    close_descriptors()?;
    reset_signals()?;
    block_signals()?;
    let pipe = Pipe::new()?;

    match fork(pipe)? {
        ForkResult::Invoker(pipe, child) => {
            finalize_invoker(pipe, child)?;
            std::process::exit(0);
        }
        ForkResult::Daemon(pipe) => {
            if let Err((error, cause)) = finalize_daemon(options) {
                exit_error(pipe, error, cause);
            } else {
                match initialization() {
                    Ok(r) => {
                        pipe.ok();
                        Ok(r)
                    }
                    Err(e) => exit_error(pipe, DaemonError::Initialization, e),
                }
            }
        }
    }
}

fn close_descriptors() -> InvocationResult {
    // Allow(clippy::needless_pass_by_value): For the filter_map flow
    #[allow(clippy::needless_pass_by_value)]
    fn file_to_fd(entry: std::fs::DirEntry) -> Option<i32> {
        entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
    }

    // Allow(clippy::needless_pass_by_value): For the map_err flow
    #[allow(clippy::needless_pass_by_value)]
    fn err_list(err: std::io::Error) -> Error {
        Error::ListOpenDescriptors(
            err.raw_os_error()
                .map_or_else(nix::errno::Errno::last, nix::errno::from_i32),
        )
    }

    std::path::PathBuf::from("/dev/fd/")
        .read_dir()
        .map_err(err_list)?
        .into_iter()
        .filter_map(Result::ok)
        .filter_map(file_to_fd)
        .filter(|fd| *fd > 2)
        .collect::<Vec<_>>()
        .into_iter()
        .map(nix::unistd::close)
        .filter_map(Result::err)
        .filter(|e| nix::Error::EBADF.ne(e))
        .map(Error::CloseDescriptors)
        .next()
        .map_or_else(|| Ok(()), Err)
}

fn reset_signals() -> InvocationResult {
    use nix::sys::signal as nix;

    nix::Signal::iterator()
        .filter(|signal| signal != &nix::SIGKILL && signal != &nix::SIGSTOP)
        .map(|signal| unsafe { nix::signal(signal, nix::SigHandler::SigDfl) })
        .find_map(Result::err)
        .map_or(Ok(()), |err| Err(Error::ResetSignals(err)))
}

fn block_signals() -> InvocationResult {
    use nix::sys::signal as nix;
    let mask = nix::SigmaskHow::SIG_BLOCK;
    let sigset = nix::SigSet::all();
    nix::sigprocmask(mask, Some(&sigset), None).map_err(Error::BlockSignals)
}

fn unblock_signals() -> nix::Result<()> {
    use nix::sys::signal as nix;
    let mask = nix::SigmaskHow::SIG_UNBLOCK;
    let sigset = nix::SigSet::all();
    nix::sigprocmask(mask, Some(&sigset), None)
}

fn fork(pipe: Pipe) -> InvocationResult<ForkResult> {
    use nix::unistd;

    match unsafe { unistd::fork() } {
        Err(err) => Err(Error::Fork(err)),
        Ok(unistd::ForkResult::Parent { child }) => Ok(ForkResult::Invoker(pipe, child)),
        Ok(unistd::ForkResult::Child) => match unistd::setsid() {
            Err(err) => exit_error(pipe, DaemonError::Setsid, err),
            Ok(_) => match unsafe { nix::unistd::fork() } {
                Err(err) => exit_error(pipe, DaemonError::Fork, err),
                Ok(unistd::ForkResult::Parent { child: _ }) => exit_success(pipe),
                Ok(unistd::ForkResult::Child) => Ok(ForkResult::Daemon(pipe)),
            },
        },
    }
}

fn finalize_invoker(pipe: Pipe, child: nix::unistd::Pid) -> InvocationResult {
    let _ = unblock_signals();
    let _ = nix::sys::wait::waitpid(child, None);
    pipe.read().and_then(Pipe::read).map(|_| ())
}

fn finalize_daemon(options: options::Options) -> DaemonResult {
    unblock_signals().map_err(|err| (DaemonError::UnblockSignals, err))?;
    nix::unistd::chdir(&options.root).map_err(|err| (DaemonError::ChangeRoot, err))?;
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    change_user(options.user, options.group)?;
    redirect_streams(options.stdin, options.stdout, options.stderr)
}

fn change_user(user: Option<nix::unistd::User>, group: Option<nix::unistd::Group>) -> DaemonResult {
    if let Some(user) = user {
        nix::unistd::setuid(user.uid).map_err(|err| (DaemonError::SetUser, err))?;
    }

    if let Some(group) = group {
        nix::unistd::setgid(group.gid).map_err(|err| (DaemonError::SetGroup, err))?;
    }

    Ok(())
}

fn redirect_streams(
    stdin: Option<options::Stdio<options::Input>>,
    stdout: Option<options::Stdio<options::Output>>,
    stderr: Option<options::Stdio<options::Output>>,
) -> DaemonResult {
    use nix::libc::{STDERR_FILENO, STDIN_FILENO, STDOUT_FILENO};
    use std::os::unix::io::{AsRawFd, RawFd};
    use DaemonError::{RedirectStderr, RedirectStdin, RedirectStdout};

    fn redirect_stream<D, F>(
        devnull_fd: &mut D,
        stdio: Option<options::Stdio<F>>,
        fd: RawFd,
        error: DaemonError,
    ) -> DaemonResult
    where
        D: FnMut(DaemonError) -> DaemonResult<RawFd>,
        F: options::File,
    {
        if let Some(stdio) = stdio {
            nix::unistd::close(fd).map_err(|err| (error, err))?;
            let new_fd = match stdio {
                options::Stdio::Null => devnull_fd(error)?,
                options::Stdio::Fd(fd) => fd,
                options::Stdio::File(file) => {
                    let open_file = file.open().map_err(|_| (error, nix::Error::last()))?;
                    let raw_fd = open_file.as_raw_fd();
                    std::mem::forget(open_file);
                    raw_fd
                }
            };
            nix::unistd::dup2(new_fd, fd).map_err(|err| (error, err))?;
        }
        Ok(())
    }

    let mut devnull = None::<std::fs::File>;

    let mut devnull_fd = |error: DaemonError| -> DaemonResult<RawFd> {
        if devnull.is_none() {
            devnull = Some(
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open("/dev/null")
                    .map_err(|_| (error, nix::Error::last()))?,
            );
        }

        Ok(devnull.as_ref().unwrap().as_raw_fd())
    };

    redirect_stream(&mut devnull_fd, stdin, STDIN_FILENO, RedirectStdin)?;
    redirect_stream(&mut devnull_fd, stdout, STDOUT_FILENO, RedirectStdout)?;
    redirect_stream(&mut devnull_fd, stderr, STDERR_FILENO, RedirectStderr)
}

#[derive(Debug)]
struct Pipe {
    reader: std::os::unix::io::RawFd,
    writer: std::os::unix::io::RawFd,
}

impl std::ops::Drop for Pipe {
    fn drop(&mut self) {
        let _ = nix::unistd::close(self.reader);
        let _ = nix::unistd::close(self.writer);
    }
}

impl Pipe {
    fn new() -> InvocationResult<Self> {
        nix::unistd::pipe()
            .map(|(reader, writer)| Self { reader, writer })
            .map_err(Error::CreatePipe)
    }

    fn read(self) -> InvocationResult<Self> {
        let mut status = [0_u8];
        nix::unistd::read(self.reader, &mut status).map_err(Error::ReadStatus)?;
        if status[0] == 0 {
            Ok(self)
        } else {
            let mut error = [0_u8; 4];
            nix::unistd::read(self.reader, &mut error).map_err(Error::ReadStatus)?;
            let error = i32::from_be_bytes(error);

            match DaemonError::from_num(status[0]) {
                Some(DaemonError::Initialization) | None => {
                    Err(Error::Initialization { code: error.into() })
                }
                Some(e) => Err(Error::daemon(e, nix::errno::from_i32(error))),
            }
        }
    }

    fn ok(self) {
        let _ = nix::unistd::write(self.writer, &[0]);
    }

    fn error(self, error: DaemonError, errno: i32) {
        let errno_ptr = errno.to_be_bytes();

        let _ = nix::unistd::write(self.writer, &[error as u8]);
        let _ = nix::unistd::write(self.writer, &errno_ptr);
    }
}

fn exit_success(pipe: Pipe) -> ! {
    pipe.ok();
    std::process::exit(0);
}

fn exit_error(pipe: Pipe, error: DaemonError, cause: impl Cause) -> ! {
    let cause = cause.into_i32();
    pipe.error(error, cause);
    std::process::exit(cause);
}

trait Cause {
    fn into_i32(self) -> i32;
}

impl Cause for nix::Error {
    fn into_i32(self) -> i32 {
        self as i32
    }
}

impl Cause for ErrorCode {
    fn into_i32(self) -> i32 {
        self.0
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn to_big_endian() {
        let int: i32 = 0x09ab_cdef;
        let array = int.to_be_bytes();

        assert_eq!(array, [0x09, 0xab, 0xcd, 0xef]);
    }
}
