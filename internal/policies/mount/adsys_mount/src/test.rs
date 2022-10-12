#[cfg(test)]
mod tests {
    use crate::{parse_entries, MountEntry};
    #[test]
    fn test_parse_entries() {
        let want: Vec<MountEntry> = vec![
            MountEntry {
                mount_path: String::from("protocol://example.com/mount/path"),
                is_anonymous: false,
            },
            MountEntry {
                mount_path: String::from("protocol://example.com/anon/mount"),
                is_anonymous: true,
            },
            MountEntry {
                mount_path: String::from("anotherprotocol://example.com/another/mount"),
                is_anonymous: false,
            },
        ];

        let got = match parse_entries(&"testdata/parse_entries/mounts".to_string()) {
            Ok(v) => v,
            Err(e) => panic!("{}", e),
        };

        assert_eq!(want, got);
    }
}
