use std::io::{Read, Write};

use pwner::Spawner;
use yad::{DaemonError, Error, ErrorCode, Stdio};

fn can_daemonize() {
    yad::daemonize().unwrap();
}

fn can_daemonize_with_init() {
    yad::daemonize_with_init(|| Ok(())).unwrap();
}

fn can_daemonize_with_options() {
    yad::with_options()
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize()
        .unwrap();
}

fn can_daemonize_with_options_and_init() {
    yad::with_options()
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize_with_init(|| Ok(()))
        .unwrap();
}

fn error_after_fork() {
    let err = yad::with_options()
        .stdin(Stdio::input("/rooty/mc/rootison"))
        .daemonize()
        .unwrap_err();

    assert_eq!(
        Error::Daemon {
            error: DaemonError::RedirectStdin,
            cause: nix::Error::ENOENT,
        },
        err
    );
}

fn error_during_init() {
    enum TestError {
        One = 1,
        Two = 2,
    }

    impl From<TestError> for i32 {
        fn from(e: TestError) -> Self {
            match e {
                TestError::One => 1,
                TestError::Two => 2,
            }
        }
    }

    let error =
        yad::daemonize_with_init(|| Result::<(), _>::Err(TestError::One.into())).unwrap_err();
    assert_eq!(Error::Initialization { code: ErrorCode(1) }, error);

    let error =
        yad::daemonize_with_init(|| Result::<(), _>::Err(TestError::Two.into())).unwrap_err();
    assert_eq!(Error::Initialization { code: ErrorCode(2) }, error);
}

fn run_test(exe: &str, test: &'static str) -> bool {
    let (mut child, _, stdout, stderr) = std::process::Command::new(exe)
        .arg(test)
        .spawn_owned()
        .unwrap()
        .eject();

    let status = child.wait().unwrap();

    if status.success() {
        println!("execution daemonize::{test} ... [32mok[m");
        true
    } else {
        println!("execution daemonize::{test} ... [31mfail[m");
        let mut buffer = String::new();
        let mut reader = std::io::BufReader::new(stdout);
        reader.read_to_string(&mut buffer).unwrap();
        if !buffer.is_empty() {
            println!();
            println!("----- stdout -----");
            print!("{buffer}");
            drop(std::io::stdout().flush());
        }

        buffer.clear();
        let mut reader = std::io::BufReader::new(stderr);
        reader.read_to_string(&mut buffer).unwrap();
        if !buffer.is_empty() {
            println!();
            println!("----- stderr -----");
            println!("{buffer}");
            drop(std::io::stdout().flush());
        }

        false
    }
}

fn main() -> std::process::ExitCode {
    let (exe, target) = {
        let mut args = std::env::args().filter(|arg| arg != "--nocapture");
        let exe = args.next().unwrap();
        let target = args.next();
        (exe, target)
    };

    if let Some(target) = target {
        match target.as_str() {
            "can_daemonize" => can_daemonize(),
            "can_daemonize_with_init" => can_daemonize_with_init(),
            "can_daemonize_with_options" => can_daemonize_with_options(),
            "can_daemonize_with_options_and_init" => can_daemonize_with_options_and_init(),
            "error_after_fork" => error_after_fork(),
            "error_during_init" => error_during_init(),
            s => panic!("Invalid test: {s}"),
        }

        std::process::ExitCode::SUCCESS
    } else {
        println!();
        let success = [
            "can_daemonize",
            "can_daemonize_with_init",
            "can_daemonize_with_options",
            "can_daemonize_with_options_and_init",
            "error_after_fork",
            "error_during_init",
        ]
        .map(|test| run_test(exe.as_str(), test))
        .into_iter()
        .all(std::convert::identity);
        println!();

        if success {
            std::process::ExitCode::SUCCESS
        } else {
            std::process::ExitCode::FAILURE
        }
    }
}
