pub mod scanners;
pub mod utils;
pub mod detect_ssh;
pub mod detect_dns;
pub mod detect_http;
pub mod detect_smtp;
pub mod detect_ftp;
pub mod fingerprint_mac;


pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
