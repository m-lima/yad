#![deny(warnings)]
#![deny(clippy::pedantic)]
#![warn(rust_2018_idioms)]
#![cfg(target_family = "unix")]

mod options;

// https://man7.org/linux/man-pages/man7/daemon.7.html
// https://fraserblog.codewise.org/rust-and-file-descriptors/

type InvocationResult<T = ()> = Result<T, Error>;

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
pub enum Error {
    #[error("failed to close file descriptors: {0}")]
    CloseDescriptors(nix::Error),

    #[error("failed to fetch open file descriptors: {0}")]
    ListOpenDescriptors(nix::Error),

    #[error("failed to reset signal handlers: {0}")]
    ResetSignals(nix::Error),

    #[error("failed to block signals: {0}")]
    BlockSignals(nix::Error),

    #[error("failed to unblock signals: {0}")]
    UnblockSignals(nix::Error),

    #[error("failed to create status reporting pipe: {0}")]
    CreatePipe(nix::Error),

    #[error("failed to fork daemon process: {0}")]
    Fork(nix::Error),

    #[error("failed to receive daemon status report: {0}")]
    ReadStatus(nix::Error),

    #[error("daemon failed to initialize: {error}: {cause}")]
    Daemon {
        error: DaemonError,
        cause: nix::Error,
    },
}

impl Error {
    fn daemon(error: DaemonError, cause: nix::Error) -> Self {
        Self::Daemon { error, cause }
    }
}

#[derive(thiserror::Error, Debug, Copy, Clone, Eq, PartialEq)]
#[repr(u8)]
pub enum DaemonError {
    #[error("failed to detach from session")]
    Setsid = 1,

    #[error("failed to double fork daemon")]
    Fork = 2,

    #[error("failed to change root directory")]
    ChangeRoot = 3,
}

#[derive(Debug)]
enum ForkResult {
    Invoker(Pipe, nix::unistd::Pid),
    Daemon(Pipe),
}

pub fn launch<F>(_daemon: F) -> InvocationResult
where
    F: FnOnce() -> (),
{
    Ok(())
}

pub fn daemonize(options: options::Options) -> InvocationResult {
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
            Ok(_) => {
                pipe.write(0);
                Ok(())
            }
            Err((error, cause)) => exit_error(pipe, error, cause),
        },
    }
}

fn close_descriptors() -> InvocationResult {
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
                nix::unistd::close(fd).map_err(|err| Error::CloseDescriptors(err.into()))?
            }
            Ok(())
        }
        Err(_) => Err(Error::ListOpenDescriptors(nix::errno::Errno::last().into())),
    }
}

fn reset_signals() -> InvocationResult {
    use nix::sys::signal as nix;

    nix::Signal::iterator()
        .filter(|signal| signal != &nix::SIGKILL && signal != &nix::SIGSTOP)
        .map(|signal| unsafe { nix::signal(signal, nix::SigHandler::SigDfl) })
        .filter_map(Result::err)
        .next()
        .map_or(Ok(()), |err| Err(Error::ResetSignals(err.into())))
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

fn finalize_daemon(options: options::Options) -> Result<(), (DaemonError, nix::Error)> {
    nix::unistd::chdir(&options.root).map_err(|err| (DaemonError::ChangeRoot, err))?;
    nix::sys::stat::umask(nix::sys::stat::Mode::empty());
    if let Some(user) = options.user {
        nix::unistd::setuid(user)?;
    }
    Ok(())
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
            .map_err(|err| Error::CreatePipe(err.into()))
    }

    fn read(self) -> InvocationResult<Self> {
        let mut status = [0u8];
        nix::unistd::read(self.reader, &mut status).map_err(Error::ReadStatus)?;
        if status[0] == 0 {
            Ok(self)
        } else {
            let mut error = [0u8; 4];
            nix::unistd::read(self.reader, &mut error).map_err(Error::ReadStatus)?;
            let error = i32::from_be_bytes(error);

            Err(Error::daemon(
                unsafe { std::mem::transmute::<u8, DaemonError>(status[0]) },
                nix::Error::from_errno(nix::errno::from_i32(error)),
            ))
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

fn exit_success(pipe: Pipe) -> ! {
    pipe.write(0);
    std::process::exit(0);
}

fn exit_error(pipe: Pipe, error: DaemonError, cause: nix::Error) -> ! {
    let errno = cause.as_errno().map_or(-1, |errno| errno as i32);
    pipe.error(error, errno);
    std::process::exit(errno);
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
