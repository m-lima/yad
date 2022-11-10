use yad::{options::Stdio, Heartbeat};

struct Error;
impl Error {
    fn as_errno(&self) -> i32 {
        1
    }
}

fn setup_daemon() -> Result<(), Error> {
    Err(Error)
}

fn run_daemon() -> ! {
    for s in (0..5).rev() {
        println!("Doing some hard work!");
        println!("Will kill myself for you in {} seconds", s);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    std::process::exit(0);
}

fn daemon_process_ok_explicit(heartbeat: Heartbeat) -> ! {
    heartbeat.ok();
    run_daemon();
}

fn daemon_process_ok_implicit() -> ! {
    run_daemon();
}

fn daemon_process_fail_explicit(heartbeat: Heartbeat) -> ! {
    match setup_daemon() {
        Ok(_) => heartbeat.ok(),
        Err(err) => {
            heartbeat.fail(err.as_errno());
            std::process::exit(err.as_errno());
        }
    }

    run_daemon();
}

fn daemon_process_fail_implicit(mut heartbeat: Heartbeat) -> Result<(), Error> {
    heartbeat.fail_on_drop();
    setup_daemon()?;
    heartbeat.ok();

    run_daemon();
}

fn daemonize_ok_explicit() -> Result<(), yad::Error> {
    let heartbeat = yad::daemonize()?;
    daemon_process_ok_explicit(heartbeat);
}

fn daemonize_ok_implicit() -> Result<(), yad::Error> {
    yad::daemonize()?;
    daemon_process_ok_implicit();
}

fn daemonize_fail_explicit() -> Result<(), yad::Error> {
    let heartbeat = yad::daemonize()?;
    daemon_process_fail_explicit(heartbeat);
}

fn daemonize_fail_implicit() -> Result<(), yad::Error> {
    let heartbeat = yad::with_options()
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize()?;
    daemon_process_fail_implicit(heartbeat).map_err(|e| yad::Error::Heartbeat {
        status: e.as_errno(),
    })
}

enum Flow {
    OkExplicit,
    OkImplicit,
    FailExplicit,
    FailImplicit,
}

impl Flow {
    fn parse(string: String) -> Option<Self> {
        match string.trim().to_lowercase().as_str() {
            "ok-explicit" => Some(Self::OkExplicit),
            "ok-implicit" => Some(Self::OkImplicit),
            "fail-explicit" => Some(Self::FailExplicit),
            "fail-implicit" => Some(Self::FailImplicit),
            _ => None,
        }
    }

    fn run(self) -> Result<(), yad::Error> {
        match self {
            Flow::OkExplicit => daemonize_ok_explicit(),
            Flow::OkImplicit => daemonize_ok_implicit(),
            Flow::FailExplicit => daemonize_fail_explicit(),
            Flow::FailImplicit => daemonize_fail_implicit(),
        }
    }
}

fn show_usage() {
    eprintln!("Expected a mode argument:");
    eprintln!("  ok-explicit");
    eprintln!("  ok-implicit");
    eprintln!("  fail-explicit");
    eprintln!("  fail-implicit");
}

fn main() -> Result<(), yad::Error> {
    if let Some(flow) = std::env::args().nth(1).and_then(Flow::parse) {
        flow.run()
    } else {
        show_usage();
        std::process::exit(1);
    }
}
