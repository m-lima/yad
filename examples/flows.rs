use yad::{options::Stdio, ErrorCode};

fn setup_daemon(should_fail: bool) -> Result<SystemResource, ErrorCode> {
    if should_fail {
        Err(ErrorCode(1))
    } else {
        Ok(SystemResource)
    }
}

// Simulates some sort of resource that it acquired during setup
struct SystemResource;

fn run_daemon(system_resource: impl Into<Option<SystemResource>>) -> ! {
    let work_string = match system_resource.into() {
        Some(_) => "Doing some hard work on these resources!",
        None => "Doing some hard work!",
    };

    for s in (0..5).rev() {
        println!("{work_string}");
        println!("Will kill myself for you in {} seconds", s);
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
    std::process::exit(0);
}

fn ok() -> Result<(), yad::Error> {
    yad::daemonize()?;
    run_daemon(None);
}

fn ok_init() -> Result<(), yad::Error> {
    let resource = yad::daemonize_with_init(|| setup_daemon(false))?;
    run_daemon(resource);
}

fn fail() -> Result<(), yad::Error> {
    let resource = yad::with_options()
        .stdout(Stdio::Null)
        .stderr(Stdio::Null)
        .daemonize_with_init(|| setup_daemon(true))?;
    run_daemon(resource);
}

enum Flow {
    Ok,
    OkInit,
    Fail,
}

impl Flow {
    fn parse(string: String) -> Option<Self> {
        match string.trim().to_lowercase().as_str() {
            "ok" => Some(Self::Ok),
            "ok-init" => Some(Self::OkInit),
            "fail" => Some(Self::Fail),
            _ => None,
        }
    }

    fn run(self) -> Result<(), yad::Error> {
        match self {
            Flow::Ok => ok(),
            Flow::OkInit => ok_init(),
            Flow::Fail => fail(),
        }
    }
}

fn show_usage() {
    eprintln!("Expected a mode argument:");
    eprintln!("  ok           An infallible daemon with no initialization");
    eprintln!("  ok-init      An infallible daemon that initializes resources");
    eprintln!("  fail         A daemon that will fail while initializing");
}

fn main() -> Result<(), yad::Error> {
    if let Some(flow) = std::env::args().nth(1).and_then(Flow::parse) {
        flow.run()
    } else {
        show_usage();
        std::process::exit(1);
    }
}
