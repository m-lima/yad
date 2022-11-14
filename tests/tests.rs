use yad::{options::Stdio, Error, ErrorCode};

#[test]
fn initialization_error() {
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

    let error = yad::with_options()
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize_with_init(|| Result::<(), _>::Err(TestError::One.into()))
        .unwrap_err();
    assert_eq!(Error::Initialization { code: ErrorCode(1) }, error);

    let error = yad::with_options()
        .stdin(Stdio::Null)
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize_with_init(|| Result::<(), _>::Err(TestError::Two.into()))
        .unwrap_err();
    assert_eq!(Error::Initialization { code: ErrorCode(2) }, error);
}
