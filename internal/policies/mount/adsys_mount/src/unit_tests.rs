#[cfg(test)]
mod lib {
    use crate::unit_tests::test_utils;
    use std::collections::HashMap;

    use crate::parse_entries;

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
            )?;

            assert_eq!(want, got);
        }
        Ok(())
    }
}

#[cfg(test)]
mod test_utils {
    use serde::{Deserialize, Serialize};
    use std::{
        fmt::Debug,
        fs::{create_dir_all, read_to_string, write},
    };

    pub fn load_and_update_golden<T>(
        golden_path: &str,
        filename: &str,
        _got: &T,
        update: bool,
    ) -> Result<T, std::io::Error>
    where
        T: Serialize + Debug + for<'a> Deserialize<'a>,
    {
        let full_path = format!("{}/{}", golden_path, filename);
        if update {
            create_dir_all(golden_path)?;

            let tmp = serde_json::to_string_pretty(_got)?;
            write(&full_path, tmp)?;
        }

        let s = read_to_string(&full_path)?;

        let want: T = serde_json::from_str(&s)?;

        Ok(want)
    }
}
