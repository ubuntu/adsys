use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    fs::{create_dir_all, read_to_string, write},
};

#[allow(dead_code)]
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
