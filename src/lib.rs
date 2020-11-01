#![deny(warnings)]
#![deny(clippy::pedantic)]
#![warn(rust_2018_idioms)]
#![cfg(target_family = "unix")]

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

    #[error("failed to create status reporting pipes: {0}")]
    CreatePipes(nix::Error),

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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum ForkResult {
    Invoker,
    Daemon,
}

pub fn launch<F>(_daemon: F) -> InvocationResult
where
    F: FnOnce() -> (),
{
    Ok(())
}

pub fn daemonize() -> InvocationResult {
    close_descriptors()?;
    reset_signals()?;
    block_signals()?;
    let pipes = ipc::create_pipes()?;

    match fork(pipes)? {
        (ForkResult::Invoker, pipes) => finalize_invoker(pipes),
        (ForkResult::Daemon, pipes) => finalize_daemon(pipes),
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

fn fork(pipes: ipc::Pipes) -> InvocationResult<(ForkResult, ipc::Pipes)> {
    use nix::unistd;

    match unsafe { unistd::fork() } {
        Err(err) => Err(Error::Fork(err)),
        Ok(unistd::ForkResult::Parent { child }) => {
            match unblock_signals().and_then(|_| nix::sys::wait::waitpid(child, None)) {
                Ok(_) => Ok((ForkResult::Invoker, pipes)),
                Err(err) => ipc::cancel_daemon(err, pipes),
            }
        }
        Ok(unistd::ForkResult::Child) => match unistd::setsid() {
            Err(err) => ipc::exit_error(DaemonError::Setsid, err, pipes),
            Ok(_) => match unsafe { nix::unistd::fork() } {
                Err(err) => ipc::exit_error(DaemonError::Fork, err, pipes),
                Ok(unistd::ForkResult::Parent { child: _ }) => ipc::exit_success(pipes),
                Ok(unistd::ForkResult::Child) => Ok((ForkResult::Daemon, pipes)),
            },
        },
    }
}

fn finalize_invoker(pipes: ipc::Pipes) -> InvocationResult {
    match ipc::read_daemon_status(pipes).and_then(ipc::read_daemon_status) {
        Ok(pipes) => ipc::exit_success(pipes),
        Err(err) => Err(err),
    }
}

fn finalize_daemon(pipes: ipc::Pipes) -> InvocationResult {
    fn finalize() -> Result<(), (DaemonError, nix::Error)> {
        nix::unistd::chdir("/").map_err(|err| (DaemonError::ChangeRoot, err))?;
        nix::sys::stat::umask(nix::sys::stat::Mode::empty());
        Ok(())
    }

    match finalize() {
        Ok(_) => {
            if ipc::should_continue(pipes) {
                Ok(())
            } else {
                std::process::exit(0)
            }
        }
        Err((error, cause)) => ipc::exit_error(error, cause, pipes),
    }
}

mod ipc {
    use super::{DaemonError, Error, ForkResult, InvocationResult};

    #[derive(Debug)]
    pub(super) struct Pipes {
        reader: std::os::unix::io::RawFd,
        writer: std::os::unix::io::RawFd,
    }

    impl std::ops::Drop for Pipes {
        fn drop(&mut self) {
            println!("Closing pipes");
            let _ = nix::unistd::close(self.reader);
            let _ = nix::unistd::close(self.writer);
        }
    }

    pub(super) fn create_pipes() -> InvocationResult<Pipes> {
        nix::unistd::pipe()
            .map(|(reader, writer)| Pipes { reader, writer })
            .map_err(|err| Error::CreatePipes(err.into()))
    }

    pub(super) fn read_daemon_status(pipes: Pipes) -> InvocationResult<Pipes> {
        let mut status = [0u8];
        println!("Reading status");
        nix::unistd::read(pipes.reader, &mut status).map_err(Error::ReadStatus)?;
        if status[0] == 0 {
            println!("All is good");
            Ok(pipes)
        } else {
            println!("Reading error");
            let mut error = [0u8; 4];
            nix::unistd::read(pipes.reader, &mut error).map_err(Error::ReadStatus)?;
            let error = i32::from_be_bytes(error);

            Err(Error::daemon(
                unsafe { std::mem::transmute::<u8, DaemonError>(status[0]) },
                nix::Error::from_errno(nix::errno::from_i32(error)),
            ))
        }
    }

    pub(super) fn cancel_daemon(
        err: nix::Error,
        pipes: Pipes,
    ) -> InvocationResult<(ForkResult, Pipes)> {
        let _ = nix::unistd::write(pipes.writer, &[255]);
        Err(Error::Fork(err))
    }

    pub(super) fn should_continue(pipes: Pipes) -> bool {
        let _ = nix::unistd::write(pipes.writer, &[0]);
        let mut status = [0u8];
        match nix::unistd::read(pipes.reader, &mut status).map_err(Error::ReadStatus) {
            Ok(_) => status[0] == 0,
            Err(_) => false,
        }
    }

    pub(super) fn exit_success(pipes: Pipes) -> ! {
        fn write_ok(pipes: Pipes) {
            let _ = nix::unistd::write(pipes.writer, &[0]);
        }

        write_ok(pipes);
        std::process::exit(0);
    }

    pub(super) fn exit_error(error: DaemonError, cause: nix::Error, pipes: Pipes) -> ! {
        fn write_error(status: i32, pipes: Pipes) {
            let status = status.to_be();
            let status_ptr = (&status as *const i32) as *const u8;
            let _ = nix::unistd::write(pipes.writer, unsafe {
                std::slice::from_raw_parts(status_ptr, 4)
            });
        }

        let _ = nix::unistd::write(pipes.writer, &[error as u8]);
        let status = cause.as_errno().map_or(-1, |errno| errno as i32);
        write_error(status, pipes);
        std::process::exit(status);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
