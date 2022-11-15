#![cfg(test)]

fn run_test(test: &'static str) {
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_test_daemonize"))
        .arg(test)
        .spawn()
        .unwrap()
        .wait_with_output()
        .unwrap();

    if !child.status.success() {
        panic!();
    }
}

#[test]
fn can_daemonize() {
    run_test("can_daemonize");
}

#[test]
fn can_daemonize_with_init() {
    run_test("can_daemonize_with_init");
}

#[test]
fn can_daemonize_with_options() {
    run_test("can_daemonize_with_options");
}

#[test]
fn can_daemonize_with_options_and_init() {
    run_test("can_daemonize_with_options_and_init");
}

#[test]
fn error_after_fork() {
    run_test("error_after_fork");
}

#[test]
fn error_during_init() {
    run_test("error_during_init");
}
