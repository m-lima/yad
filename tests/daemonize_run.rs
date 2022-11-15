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

fn main() {
    match std::env::args()
        .nth(1)
        .expect("Expected a test name")
        .as_str()
    {
        "can_daemonize" => can_daemonize(),
        "can_daemonize_with_init" => can_daemonize_with_init(),
        "can_daemonize_with_options" => can_daemonize_with_options(),
        "can_daemonize_with_options_and_init" => can_daemonize_with_options_and_init(),
        "error_after_fork" => error_after_fork(),
        "error_during_init" => error_during_init(),
        s => panic!("Invalid test: {s}"),
    }
}
