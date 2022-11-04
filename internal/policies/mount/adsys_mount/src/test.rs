#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{parse_entries, test_utils};

    #[test]
    fn test_parse_entries() -> Result<(), std::io::Error> {
        struct TestCase {
            file: &'static str,
        }

        let tests: HashMap<&str, TestCase> = HashMap::from([
            (
                "mounts file with one entry",
                TestCase {
                    file: "mounts_with_one_entry",
                },
            ),
            (
                "mounts file with multiple entries",
                TestCase {
                    file: "mounts_with_multiple_entries",
                },
            ),
            (
                "mounts file with anonymous entries",
                TestCase {
                    file: "mounts_with_anonymous_entries",
                },
            ),
            (
                "empty mounts file",
                TestCase {
                    file: "mounts_with_no_entry",
                },
            ),
            (
                "mounts file with bad entries",
                TestCase {
                    file: "mounts_with_bad_entries",
                },
            ),
        ]);

        for test in tests.iter() {
            let testdata = "testdata/test_parse_entries";

            let got = parse_entries(&format!("{}/{}", testdata, (test.1).file))?;

            let want = test_utils::load_and_update_golden(
                &format!("{}/{}", testdata, "golden"),
                test.0,
                &got,
                false,
            );

            match want {
                Ok(w) => {
                    for i in 0..w.len() {
                        assert_eq!(w[i], got[i]);
                    }
                }
                Err(e) => panic!("{}", e),
            }
        }
        Ok(())
    }
}
