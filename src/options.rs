//! Configuration for starting the daemon.
//!
//! # Example
//! ```no_run
//! match yad::daemonize() {
//!     Ok(_) => println!("I'm a daemon"),
//!     Err(err) => eprintln!("Failed to launch daemon: {}", err),
//! }
//! ```
//!
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

/// Used by [`Stdio`](enum.Stdio.html) to represent a file.
pub trait File {
    /// Opens the file.
    ///
    /// # Errors
    /// If the file fails to be created or opened.
    fn open(&self) -> std::io::Result<std::fs::File>;
}

/// Used by [`Stdio`](enum.Stdio.html) to represent an input file.
pub struct Input {
    path: std::path::PathBuf,
    create: bool,
}

impl Input {
    fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            create: false,
        }
    }

    /// The file should be created if it does not exist.
    #[must_use]
    pub fn create(mut self) -> Self {
        self.create = true;
        self
    }
}

impl std::convert::From<Input> for Stdio<Input> {
    fn from(input: Input) -> Self {
        Self::File(input)
    }
}

impl File for Input {
    fn open(&self) -> std::io::Result<std::fs::File> {
        if self.create {
            std::fs::File::create(&self.path)?;
        }

        std::fs::File::open(&self.path)
    }
}

/// Used by [`Stdio`](enum.Stdio.html) to represent an output file.
pub struct Output {
    path: std::path::PathBuf,
    append: bool,
}

impl Output {
    fn new<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self {
            path: path.into(),
            append: false,
        }
    }

    /// The file should be open in append mode.
    #[must_use]
    pub fn append(mut self) -> Self {
        self.append = true;
        self
    }
}

impl std::convert::From<Output> for Stdio<Output> {
    fn from(output: Output) -> Self {
        Self::File(output)
    }
}

impl File for Output {
    fn open(&self) -> std::io::Result<std::fs::File> {
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(!self.append)
            .append(self.append)
            .open(&self.path)
    }
}

/// Possible values for redirecting the daemons standard input and outputs.
pub enum Stdio<F: File> {
    /// A file.
    File(F),
    /// A raw unix file descriptor.
    Fd(i32),
    /// Points to `/dev/null`.
    Null,
}

impl Stdio<Input> {
    /// Create a new input file.
    pub fn input<P: Into<std::path::PathBuf>>(path: P) -> Input {
        Input::new(path)
    }
}

impl Stdio<Output> {
    /// Create a new output file.
    pub fn output<P: Into<std::path::PathBuf>>(path: P) -> Output {
        Output::new(path)
    }
}

/// Holds the configuration to start the daemon with.
///
/// By deafult all values are `None` and the daemon starts with the working directory set as `/`.
pub struct Options {
    pub(super) user: Option<nix::unistd::User>,
    pub(super) group: Option<nix::unistd::Group>,
    pub(super) root: std::path::PathBuf,
    pub(super) stdin: Option<Stdio<Input>>,
    pub(super) stdout: Option<Stdio<Output>>,
    pub(super) stderr: Option<Stdio<Output>>,
}

impl Options {
    pub(super) fn new() -> Self {
        Self {
            user: None,
            group: None,
            root: std::path::PathBuf::from("/"),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }

    /// Starts the daemon.
    ///
    /// When this method returns, if it is a failure, it is guaranteed to be running on the
    /// original process. If it is a success, it is guaranteed to be running as a daemon.
    ///
    /// # Errors
    /// If the daemonizing operation fails.
    ///
    /// The invoking process, i.e. the process that called
    /// [`daemonize()`](struct.Options.html#method.daemonize), will handle the error. The forked
    /// process will be guaranteed to be terminated and the invoking process will own all resources.
    ///
    /// # See also
    /// [`daemonize()`](fn.daemonize.html)
    pub fn daemonize(self) -> super::InvocationResult {
        super::daemonize_inner(self, || Ok(()))
    }

    /// Starts the daemon with default options executing `initialization` after forking the process.
    ///
    /// When this method returns, if it is a failure, it is guaranteed to be running on the
    /// original process. If it is a success, it is guaranteed to be running as a daemon.
    ///
    /// Therefore, when this method returns, if it is a failure, it is guaranteed to be running on
    /// the original process. If it is a success, it is guaranteed to be running as a daemon.
    ///
    /// If the initialization fails, the error will be converted to an `i32` representation and sent
    /// though the pipe back to the invoking process. The forked daemon will unwind its
    /// initialization stack, and terminate without unwind any further. The invoking process will
    /// own all shared resources.
    ///
    /// # Errors
    /// If the daemonizing operation fails or if the initialization fails.
    ///
    /// The invoking process, i.e. the process that called [`daemonize()`](fn.daemonize.html),
    /// will handle the error. The forked process will be guaranteed to be terminated and the
    /// invoking process will own all resources.
    ///
    /// Any resources acquired during `initialization` execution will be owned just by the forked
    /// process and will be unwound and dropped upon error.
    ///
    /// # See also
    /// [`daemonize_with_init()`](fn.daemonize_with_init.html)
    pub fn daemonize_with_init<F, R>(self, initialization: F) -> super::InvocationResult<R>
    where
        F: FnOnce() -> Result<R, super::ErrorCode>,
    {
        super::daemonize_inner(self, initialization)
    }

    /// Sets the UID for the daemon.
    #[must_use]
    pub fn user(mut self, user: nix::unistd::User) -> Self {
        self.user = Some(user);
        self
    }

    /// Sets the GID for the daemon.
    #[must_use]
    pub fn group(mut self, group: nix::unistd::Group) -> Self {
        self.group = Some(group);
        self
    }

    /// Sets the working directory for the daemon.
    #[must_use]
    pub fn root<P: Into<std::path::PathBuf>>(mut self, root: P) -> Self {
        self.root = root.into();
        self
    }

    /// Sets the standard input for the daemon.
    #[must_use]
    pub fn stdin<I: Into<Stdio<Input>>>(mut self, stdin: I) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    /// Sets the standard output for the daemon.
    #[must_use]
    pub fn stdout<O: Into<Stdio<Output>>>(mut self, stdout: O) -> Self {
        self.stdout = Some(stdout.into());
        self
    }

    /// Sets the standard error output for the daemon.
    #[must_use]
    pub fn stderr<O: Into<Stdio<Output>>>(mut self, stderr: O) -> Self {
        self.stderr = Some(stderr.into());
        self
    }
}
