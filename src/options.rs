pub trait File {
    /// Opens the file
    ///
    /// # Errors
    /// If the file fails to be created or opened
    fn open(&self) -> std::io::Result<std::fs::File>;
}

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

    #[must_use]
    pub fn create(mut self) -> Self {
        self.create = true;
        self
    }
}

impl std::convert::Into<Stdio<Input>> for Input {
    fn into(self) -> Stdio<Input> {
        Stdio::File(self)
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

    #[must_use]
    pub fn append(mut self) -> Self {
        self.append = true;
        self
    }
}

impl std::convert::Into<Stdio<Output>> for Output {
    fn into(self) -> Stdio<Output> {
        Stdio::File(self)
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

pub enum Stdio<F: File> {
    File(F),
    Fd(i32),
    Null,
}

impl Stdio<Input> {
    pub fn input<P: Into<std::path::PathBuf>>(path: P) -> Input {
        Input::new(path)
    }
}

impl Stdio<Output> {
    pub fn output<P: Into<std::path::PathBuf>>(path: P) -> Output {
        Output::new(path)
    }
}

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

    /// Starts the daemon
    ///
    /// # Errors
    /// If the daemonizing operation fails
    pub fn daemonize(self) -> super::InvocationResult<super::Heartbeat> {
        super::daemonize_inner(self)
    }

    #[must_use]
    pub fn user(mut self, user: nix::unistd::User) -> Self {
        self.user = Some(user);
        self
    }

    #[must_use]
    pub fn group(mut self, group: nix::unistd::Group) -> Self {
        self.group = Some(group);
        self
    }

    #[must_use]
    pub fn root<P: Into<std::path::PathBuf>>(mut self, root: P) -> Self {
        self.root = root.into();
        self
    }

    #[must_use]
    pub fn stdin<I: Into<Stdio<Input>>>(mut self, stdin: I) -> Self {
        self.stdin = Some(stdin.into());
        self
    }

    #[must_use]
    pub fn stdout<O: Into<Stdio<Output>>>(mut self, stdout: O) -> Self {
        self.stdout = Some(stdout.into());
        self
    }

    #[must_use]
    pub fn stderr<O: Into<Stdio<Output>>>(mut self, stderr: O) -> Self {
        self.stderr = Some(stderr.into());
        self
    }
}
