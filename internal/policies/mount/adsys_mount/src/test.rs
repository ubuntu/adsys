#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use crate::{parse_entries, test_utils};

    #[test]
    fn test_parse_entries() -> Result<(), std::io::Error> {
        struct TestCase {
            file: String,
        }

        let tests: HashMap<&str, TestCase> = HashMap::from([
            (
                "mounts file with one entry",
                TestCase {
                    file: "mounts_with_one_entry".to_string(),
                },
            ),
            (
                "mounts file with multiple entries",
                TestCase {
                    file: "mounts_with_multiple_entries".to_string(),
                },
            ),
            (
                "mounts file with anonymous entries",
                TestCase {
                    file: "mounts_with_anonymous_entries".to_string(),
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
                    assert_eq!(w, format!("{:?}", got))
                }
                Err(e) => panic!("{}", e),
            }
        }
        Ok(())
    }
}
