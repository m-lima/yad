#![deny(warnings)]
#![deny(clippy::pedantic)]
#![warn(rust_2018_idioms)]
#![cfg(target_family = "unix")]

pub mod options;

// https://man7.org/linux/man-pages/man7/daemon.7.html
// https://fraserblog.codewise.org/rust-and-file-descriptors/

type InvocationResult<T = ()> = Result<T, Error>;
type DaemonResult<T = ()> = Result<T, (DaemonError, nix::Error)>;

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("Daemon pid file already exists")]
    DaemonAlreadyRunning,

    #[error("Failed to close file descriptors: {0}")]
    CloseDescriptors(nix::Error),

    #[error("Failed to fetch open file descriptors: {0}")]
    ListOpenDescriptors(nix::Error),

    #[error("Failed to reset signal handlers: {0}")]
    ResetSignals(nix::Error),

    #[error("Failed to block signals: {0}")]
    BlockSignals(nix::Error),

    #[error("Failed to create status reporting pipe: {0}")]
    CreatePipe(nix::Error),

    #[error("Failed to fork daemon process: {0}")]
    Fork(nix::Error),

    #[error("Failed to receive daemon status report: {0}")]
    ReadStatus(nix::Error),

    #[error("Daemon failed to initialize: {error}: {cause}")]
    Daemon {
        error: DaemonError,
        cause: nix::Error,
    },

    #[error("Daemon sent failed heart beat: Status code: {status}")]
    Heartbeat { status: i32 },
}

impl Error {
    fn daemon(error: DaemonError, cause: nix::Error) -> Self {
        Self::Daemon { error, cause }
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum DaemonError {
    #[error("Failed heart beat")]
    Heartbeat = 1,

    #[error("Failed to detach from session")]
    Setsid = 2,

    #[error("Failed to double fork daemon")]
    Fork = 3,

    #[error("Failed to change root directory")]
    ChangeRoot = 4,

    #[error("Failed to set user")]
    SetUser = 5,

    #[error("Failed to set group")]
    SetGroup = 6,

    #[error("Failed to unblock signals")]
    UnblockSignals = 7,

    #[error("Failed to close file descriptors")]
    CloseDescriptors = 8,

    #[error("Failed to fetch open file descriptors")]
    ListOpenDescriptors = 9,

    #[error("Failed to reset signal handlers")]
    ResetSignals = 10,

    #[error("Failed to redirect stdin")]
    RedirectStdin = 11,

    #[error("Failed to redirect stdout")]
    RedirectStdout = 12,

    #[error("Failed to redirect stderr")]
    RedirectStderr = 13,
}

#[derive(Debug)]
enum ForkResult {
    Invoker(Pipe, nix::unistd::Pid),
    Daemon(Pipe),
}

/// Starts the daemon
///
/// # Errors
/// If the daemonizing operation fails
pub fn daemonize() -> InvocationResult<Heartbeat> {
    daemonize_inner(options::Options::new())
}

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
            Ok(_) => Ok(Heartbeat(Some(pipe))),
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

pub struct Heartbeat(Option<Pipe>);

impl Heartbeat {
    pub fn fail(mut self, errno: i32) {
        if let Some(pipe) = self.0.take() {
            pipe.error(DaemonError::Heartbeat, errno);
        }
    }

    pub fn ok(mut self) {
        if let Some(pipe) = self.0.take() {
            pipe.write(0);
        }
    }
}

impl Drop for Heartbeat {
    fn drop(&mut self) {
        if let Some(pipe) = self.0.take() {
            pipe.write(0);
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
