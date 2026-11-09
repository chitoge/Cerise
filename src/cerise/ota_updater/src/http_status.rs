//! Compatibility name for the status validation now shared by all bounded
//! download clients. Keeping this small facade avoids churn in the updater's
//! independently tested policy targets.

pub use cerise_http_download::{validate_status_line, MAX_STATUS_LINE_BYTES};

#[cfg(test)]
mod tests {
    use super::{validate_status_line, MAX_STATUS_LINE_BYTES};

    #[test]
    fn accepts_only_the_two_supported_http_versions_with_200() {
        for line in [
            b"HTTP/1.0 200 OK".as_slice(),
            b"HTTP/1.1 200 OK".as_slice(),
            b"HTTP/1.1 200 ".as_slice(),
        ] {
            assert!(validate_status_line(line).is_ok(), "{line:?}");
        }
    }

    #[test]
    fn rejects_substring_status_code_tricks_and_bad_syntax() {
        for line in [
            b"HTTP/1.1 2000 OK".as_slice(),
            b"HTTP/1.1 1200 OK".as_slice(),
            b"HTTP/1.1 0200 OK".as_slice(),
            b"HTTP/1.1 200OK".as_slice(),
            b"HTTP/1.1 200".as_slice(),
            b"HTTP/2.0 200 OK".as_slice(),
            b"prefix HTTP/1.1 200 OK".as_slice(),
            b"HTTP/1.1\t200 OK".as_slice(),
        ] {
            assert!(validate_status_line(line).is_err(), "accepted {line:?}");
        }
    }

    #[test]
    fn rejects_controls_and_oversized_lines() {
        for line in [
            b"HTTP/1.1 200 OK\0".as_slice(),
            b"HTTP/1.1 200 OK\x09".as_slice(),
            b"HTTP/1.1 200 OK\x1f".as_slice(),
            b"HTTP/1.1 200 OK\x7f".as_slice(),
            b"HTTP/1.1 200 OK\nnext".as_slice(),
            b"HTTP/1.1 200 OK\rnext".as_slice(),
        ] {
            assert!(validate_status_line(line).is_err(), "accepted {line:?}");
        }

        let mut oversized = b"HTTP/1.1 200 ".to_vec();
        oversized.extend(std::iter::repeat(b'A').take(MAX_STATUS_LINE_BYTES));
        assert!(validate_status_line(&oversized).is_err());
    }
}
