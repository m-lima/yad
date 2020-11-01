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

pub struct DaemonOptions {
    pid_file: Option<std::path::PathBuf>,
    user: Option<User>,
    group: Option<Group>,
    root: std::path::PathBuf,
    stdin: Stdio,
    stdout: Stdio,
    stderr: Stdio,
}
