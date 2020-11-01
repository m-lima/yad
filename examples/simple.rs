fn main() {
    match daemon::launch() {
        Ok(_) => println!("I'm a daemon"),
        Err(err) => eprintln!("Failed to lauch daemon: {}", err),
    }
}
