
pub fn pretty_print_collection<T: std::fmt::Debug>(title: &str, collection: &[T], color: &str) {
    println!("\x1b[1;{}m{}\x1b[0m", color, title);
    for (i, item) in collection.iter().enumerate() {
        println!("\x1b[{}m{:>3}: {:?}\x1b[0m", color, i + 1, item);
    }
    println!();
}

pub fn pretty_print_summary(live_count: usize, not_alive_count: usize) {
    println!("\x1b[1;32mLive Hosts: {}\x1b[0m", live_count);
    println!("\x1b[1;31mNot Alive Hosts: {}\x1b[0m", not_alive_count);
}