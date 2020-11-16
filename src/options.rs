pub struct Input {
    pub(super) path: std::path::PathBuf,
}

pub struct Output {
    pub(super) path: std::path::PathBuf,
    pub(super) append: bool,
}

pub trait StdioPath {
    fn read(&self) -> bool;
    fn write(&self) -> bool;
    fn append(&self) -> bool;
    fn path(&self) -> &std::path::Path;
}

impl StdioPath for Input {
    fn read(&self) -> bool {
        true
    }

    fn write(&self) -> bool {
        false
    }

    fn append(&self) -> bool {
        false
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl StdioPath for Output {
    fn read(&self) -> bool {
        false
    }

    fn write(&self) -> bool {
        true
    }

    fn append(&self) -> bool {
        self.append
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

pub enum Stdio<P: StdioPath> {
    Path(P),
    Fd(i32),
    Null,
}

impl Stdio<Input> {
    pub fn open<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self::Path(Input { path: path.into() })
    }
}

impl Stdio<Output> {
    pub fn create<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self::Path(Output {
            path: path.into(),
            append: false,
        })
    }

    pub fn append<P: Into<std::path::PathBuf>>(path: P) -> Self {
        Self::Path(Output {
            path: path.into(),
            append: true,
        })
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

    pub fn daemonize(self) -> super::InvocationResult<super::Heartbeat> {
        super::daemonize_inner(self)
    }

    pub fn user(mut self, user: nix::unistd::User) -> Self {
        self.user = Some(user);
        self
    }

    pub fn group(mut self, group: nix::unistd::Group) -> Self {
        self.group = Some(group);
        self
    }

    pub fn root<P: Into<std::path::PathBuf>>(mut self, root: P) -> Self {
        self.root = root.into();
        self
    }

    pub fn stdin(mut self, stdin: Stdio<Input>) -> Self {
        self.stdin = Some(stdin);
        self
    }

    pub fn stdout(mut self, stdout: Stdio<Output>) -> Self {
        self.stdout = Some(stdout);
        self
    }

    pub fn stderr(mut self, stderr: Stdio<Output>) -> Self {
        self.stderr = Some(stderr);
        self
    }
}
