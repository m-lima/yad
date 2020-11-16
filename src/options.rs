#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum User {
    Name(String),
    Id(u32),
}

impl std::convert::From<String> for User {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl std::convert::From<&str> for User {
    fn from(name: &str) -> Self {
        Self::Name(String::from(name))
    }
}

impl std::convert::From<u32> for User {
    fn from(id: u32) -> Self {
        Self::Id(id)
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd)]
pub enum Group {
    Name(String),
    Id(u32),
}

impl std::convert::From<String> for Group {
    fn from(name: String) -> Self {
        Self::Name(name)
    }
}

impl std::convert::From<&str> for Group {
    fn from(name: &str) -> Self {
        Self::Name(String::from(name))
    }
}

impl std::convert::From<u32> for Group {
    fn from(id: u32) -> Self {
        Self::Id(id)
    }
}

pub enum Stdio {
    File(std::fs::File),
    Fd(i32),
    Null,
}

impl std::os::unix::io::AsRawFd for Stdio {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        match self {
            Self::File(file) => file.as_raw_fd(),
            Self::Fd(fd) => *fd,
            Self::Null => {
                let file = std::fs::File::open("/dev/null").unwrap();
                file.as_raw_fd()
            }
        }
    }
}

pub struct Options {
    pub(super) user: Option<nix::unistd::User>,
    pub(super) group: Option<nix::unistd::Group>,
    pub(super) root: std::path::PathBuf,
    pub(super) stdin: Option<Stdio>,
    pub(super) stdout: Option<Stdio>,
    pub(super) stderr: Option<Stdio>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            user: None,
            group: None,
            root: std::path::PathBuf::from("/"),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }
}
