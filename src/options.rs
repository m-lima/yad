pub enum User {
    Name(String),
    Id(u32),
}

pub enum Group {
    Name(String),
    Id(u32),
}

pub enum Stdio {
    File(std::path::PathBuf),
    Fd(i32),
    Null,
}

pub struct Options {
    pub(super) pid_file: Option<std::path::PathBuf>,
    pub(super) user: Option<User>,
    pub(super) group: Option<Group>,
    pub(super) root: std::path::PathBuf,
    pub(super) stdin: Option<Stdio>,
    pub(super) stdout: Option<Stdio>,
    pub(super) stderr: Option<Stdio>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            pid_file: None,
            user: None,
            group: None,
            root: std::path::PathBuf::from("/"),
            stdin: None,
            stdout: None,
            stderr: None,
        }
    }
}
