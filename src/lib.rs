#![deny(warnings, missing_docs, clippy::pedantic)]
#![warn(rust_2018_idioms)]
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
/// These errors are received in the invoking process, i.e. the proccess that called [`daemonize()`](fn.daemonize.html).
#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
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

    /// The [`Heartbeat`](struct.Heartbeat.html) from the daemon reported an error
    #[error("Daemon sent failed heart beat: Status code: {status}")]
    Heartbeat {
        /// The status code reported back by the daemon
        status: i32,
    },
}

impl Error {
    fn daemon(error: DaemonError, cause: nix::Error) -> Self {
        Self::Daemon { error, cause }
    }
}

/// Wrapped errors that can happen after the daemon has forked.
///
/// The error is reported by another process through pipes and received by the invoking process,
/// i.e. the process that called [`daemonize()`](fn.daemonize.html), will handle the error.
///
/// The forked process will be guaranteed to be stopped, unless the error is a
/// [`Heartbeat`](enum.DaemonError.html#variant.Heartbeat), in which case the forked process is
/// responsible for terminating after cleaning up.
///
/// # See also
/// [`Error`](enum.Error.html)
#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum DaemonError {
    /// The [`Heartbeat`](struct.Heartbeat.html) from the daemon reported an error
    #[error("Failed heart beat")]
    Heartbeat = 1,

    /// Failure detaching from session
    #[error("Failed to detach from session")]
    Setsid = 2,

    /// Failure during the second call to `fork()`
    #[error("Failed to double fork daemon")]
    Fork = 3,

    /// Failure changing root directory
    #[error("Failed to change root directory")]
    ChangeRoot = 4,

    /// Failure setting UID
    #[error("Failed to set user")]
    SetUser = 5,

    /// Failure setting GID
    #[error("Failed to set group")]
    SetGroup = 6,

    /// Failure unblocking the signals
    #[error("Failed to unblock signals")]
    UnblockSignals = 7,

    /// Failure closing file descriptors
    #[error("Failed to close file descriptors")]
    CloseDescriptors = 8,

    /// Failure listing open file descriptors
    #[error("Failed to fetch open file descriptors")]
    ListOpenDescriptors = 9,

    /// Failure resetting signal handlers
    #[error("Failed to reset signal handlers")]
    ResetSignals = 10,

    /// Failure redirecting STDIN
    #[error("Failed to redirect stdin")]
    RedirectStdin = 11,

    /// Failure redirecting STDOUT
    #[error("Failed to redirect stdout")]
    RedirectStdout = 12,

    /// Failure redirecting STDERR
    #[error("Failed to redirect stderr")]
    RedirectStderr = 13,
}

#[derive(Debug)]
enum ForkResult {
    Invoker(Pipe, nix::unistd::Pid),
    Daemon(Pipe),
}

/// Starts the daemon with default options.
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
/// will handle the error. The forked process will be guaranteed to be stopped, unless the
/// error is a [`Heartbeat`](enum.DaemonError.html#variant.Heartbeat), in which case the
/// forked process is responsible for terminating after cleaning up.
///
/// # See also
/// [`with_options()`](fn.with_options.html)
pub fn daemonize() -> InvocationResult<Heartbeat> {
    daemonize_inner(options::Options::new())
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
/// # Errors
/// If the daemonizing operation fails.
///
/// The invoking process, i.e. the process that called
/// [`daemonize()`](options/struct.Options.html#method.daemonize), will handle the
/// error. The forked process will be guaranteed to be stopped, unless the error is a
/// [`Heartbeat`](enum.DaemonError.html#variant.Heartbeat), in which case the forked process is
/// responsible for terminating after cleaning up.
///
/// # See also
/// [`daemonize()`](fn.daemonize.html)
#[must_use]
pub fn with_options() -> options::Options {
    options::Options::new()
}

fn daemonize_inner(options: options::Options) -> InvocationResult<Heartbeat> {
    close_descriptors()?;
    reset_signals()?;
    block_signals()?;
    let pipe = Pipe::new()?;

    match fork(pipe)? {
        ForkResult::Invoker(pipe, child) => match finalize_invoker(pipe, child) {
            Ok(_) => std::process::exit(0),
            Err(err) => Err(err),
        },
        ForkResult::Daemon(pipe) => match finalize_daemon(options) {
            Ok(_) => Ok(Heartbeat(Some(pipe), false)),
            Err((error, cause)) => exit_error(pipe, error, cause),
        },
    }
}

fn close_descriptors() -> InvocationResult {
    // Allowed because of the filter_map flow
    #[allow(clippy::needless_pass_by_value)]
    fn file_to_fd(entry: std::fs::DirEntry) -> Option<i32> {
        entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
    }

    let fd_dir = std::path::PathBuf::from("/dev/fd/");

    match fd_dir.read_dir() {
        Ok(dir) => {
            for fd in dir
                .filter_map(Result::ok)
                .filter_map(file_to_fd)
                .filter(|fd| fd > &2)
            {
                nix::unistd::close(fd).map_err(Error::CloseDescriptors)?
            }
            Ok(())
        }
        Err(_) => Err(Error::ListOpenDescriptors(nix::errno::Errno::last().into())),
    }
}

fn reset_signals() -> InvocationResult {
    use nix::sys::signal as nix;

    // Allowed because it is just more readable
    #[allow(clippy::filter_map)]
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
                    // Allowed because we grab the error from OS
                    #[allow(clippy::map_err_ignore)]
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
        // Allowed because we grab the error from OS
        #[allow(clippy::map_err_ignore)]
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

            if status[0] == DaemonError::Heartbeat as u8 {
                Err(Error::Heartbeat { status: error })
            } else {
                Err(Error::daemon(
                    unsafe { std::mem::transmute::<u8, DaemonError>(status[0]) },
                    nix::Error::from_errno(nix::errno::from_i32(error)),
                ))
            }
        }
    }

    fn write(self, status: u8) {
        let _ = nix::unistd::write(self.writer, &[status]);
    }

    fn error(self, error: DaemonError, errno: i32) {
        let errno = errno.to_be();
        let errno_ptr = (&errno as *const i32) as *const u8;

        let _ = nix::unistd::write(self.writer, &[error as u8]);
        let _ = nix::unistd::write(self.writer, unsafe {
            std::slice::from_raw_parts(errno_ptr, 4)
        });
    }
}

/// Allows reporting back to the invoker process if the initialization of the service was
/// successful or not.
///
/// The heartbeat is sent after the daemonizing process has succeeded and it is reported back by
/// the daemon itself. This is, therefore, a means of reporting a healthy running daemon after all
/// configuration.
///
/// The struct will automatically send a success signal when it gets dropped. This behavior can be
/// changed by setting [`fail_on_drop`](struct.Heartbeat.html#method.fail_on_drop), which is useful
/// when using the `?` error propagation early exit.
///
/// # Example
///
/// ### Reporting heartbeat on drop
/// **Infallible:**
/// ```no_run
/// # use yad::Heartbeat;
/// fn daemon_process() -> ! {
///     loop {
///         println!("loooooooooop");
///     }
/// }
///
/// fn start() -> Result<(), yad::Error> {
///     yad::daemonize()?;
///     daemon_process();
/// }
/// ```
///
/// **Fallible:**
/// ```no_run
/// # use yad::Heartbeat;
/// # fn setup_daemon() -> Result<(), yad::Error> {
/// #     Err(yad::Error::Heartbeat{ status: 1 })
/// # }
/// fn daemon_process(mut heartbeat: Heartbeat) -> Result<(), yad::Error> {
///     heartbeat.fail_on_drop();
///     setup_daemon()?;
///     heartbeat.ok();
///
///     loop {
///         println!("loooooooooop");
///     }
/// }
///
/// fn start() -> Result<(), yad::Error> {
///     let heartbeat = yad::daemonize()?;
///     daemon_process(heartbeat)
/// }
/// ```
///
/// ### Explicitly reporting heartbeat
///
/// **Infallible:**
/// ```no_run
/// # use yad::Heartbeat;
/// fn daemon_process(heartbeat: Heartbeat) -> ! {
///     heartbeat.ok();
///     loop {
///         println!("loooooooooop");
///     }
/// }
///
/// fn start() -> Result<(), yad::Error> {
///     let heartbeat = yad::daemonize()?;
///     daemon_process(heartbeat);
/// }
/// ```
///
/// **Fallible:**
/// ```no_run
/// # use yad::Heartbeat;
/// # struct Error;
/// # impl Error {
/// #   fn as_errno(&self) -> i32 {
/// #       1
/// #   }
/// # }
/// # fn setup_daemon() -> Result<(), Error> {
/// #     Err(Error)
/// # }
/// fn daemon_process(heartbeat: Heartbeat) -> ! {
///     match setup_daemon() {
///         Ok(_) => heartbeat.ok(),
///         Err(err) => {
///             heartbeat.fail(err.as_errno());
///             std::process::exit(err.as_errno());
///         }
///     }
///
///     loop {
///         println!("loooooooooop");
///     }
/// }
///
/// fn start() -> Result<(), yad::Error> {
///     let heartbeat = yad::daemonize()?;
///     daemon_process(heartbeat);
/// }
/// ```
pub struct Heartbeat(Option<Pipe>, bool);

impl Heartbeat {
    /// Sets to emit a failure when dropped.
    ///
    /// The error emitted on drop will be of carry `UnknownErrno`. To specify an `errno`,
    /// explicitly call [`fail()`](struct.Heartbeat.htnl#method.fail).
    pub fn fail_on_drop(&mut self) {
        self.1 = true;
    }

    /// Reports back to the invoking process that the daemon failed to initialize.
    ///
    /// It is best practice to terminate the failed daemon after cleaning up.
    pub fn fail(mut self, errno: i32) {
        if let Some(pipe) = self.0.take() {
            pipe.error(DaemonError::Heartbeat, errno);
        }
    }

    /// Reports back to the invoking process that the daemon successfully initialized and it is
    /// running.
    pub fn ok(mut self) {
        if let Some(pipe) = self.0.take() {
            pipe.write(0);
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        if let Some(pipe) = self.0.take() {
            if self.1 {
                pipe.error(DaemonError::Heartbeat, 0);
            } else {
                pipe.write(0);
            }
        }
    }
}

fn exit_success(pipe: Pipe) -> ! {
    pipe.write(0);
    std::process::exit(0);
}

fn exit_error(pipe: Pipe, error: DaemonError, cause: nix::Error) -> ! {
    let errno = cause.as_errno().map_or(-1, |errno| errno as i32);
    pipe.error(error, errno);
    std::process::exit(errno);
}
