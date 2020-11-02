fn main() {
    match daemon::daemonize() {
        Ok(_) => println!("I'm a daemon"),
        Err(err) => eprintln!("Failed to lauch daemon: {}", err),
    }
}
