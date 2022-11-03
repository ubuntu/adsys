use std::{
    fmt::Debug,
    fs::{create_dir_all, read_to_string, write},
};

#[allow(dead_code)]
pub fn load_and_update_golden<T>(
    golden_path: &str,
    filename: &str,
    _got: T,
    update: bool,
) -> Result<String, std::io::Error>
where
    T: Debug,
{
    let full_path = format!("{}/{}", golden_path, filename);
    if update {
        create_dir_all(golden_path)?;
        write(&full_path, format!("{:?}", _got))?;
    }

    let want = read_to_string(full_path.as_str());

    want
}
