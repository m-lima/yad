# Yet Another Daemonizer
[![Github](https://github.com/m-lima/yad/workflows/build/badge.svg)](https://github.com/m-lima/yad/actions?workflow=build)
[![MIT licensed](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Cargo](https://img.shields.io/crates/v/yad.svg)](
https://crates.io/crates/yad)
[![Documentation](https://docs.rs/yad/badge.svg)](https://docs.rs/yad)

Yet Another Daemonizer is a daemonizing crate to easily, simply, and **correctly** create legacy
daemons.

This crate focuses on manually creating a background process which is not managed by a
supervisor such as systemd or launchd. It strives to follow all the best practices
to correctly daemonize a process.

## Example
```rust
match yad::with_options()
    .stdin(yad::options::Stdio::Null)
    .stderr(yad::options::Stdio::Null)
    .stdout(yad::options::Stdio::output("/var/log/daemon.log"))
    .daemonize()
{
    Ok(_) => println!("I'm a daemon"),
    Err(err) => eprintln!("Failed to lauch daemon: {}", err),
}
```

## References
* [Man page for daemon()](https://man7.org/linux/man-pages/man7/daemon.7.html)
* [Reference project in C](https://chaoticlab.io/c/c++/unix/2018/10/01/daemonize.html)
