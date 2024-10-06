use regex::Regex;
use std::io::{self, Write};

pub fn timeconvert(time: &String) -> Result<u32, String> {
    let re = Regex::new(r"(?P<value>\d+)(?P<unit>[dmh]*)").unwrap();

    /*
     * Parse timestring and divide in value and unit
     */
    let cap = match re.captures(time) {
        None => Err(format!("Unknown Timeformat: {}", time))?,
        Some(x) => x
    };

    /*
     * If no value is set, use 1 as default
     */
    let cap_val = match cap.name("value") {
        None => "1",
        Some(x) => x.as_str()
    };

    /*
     * If no unit is set, use minute as default
     */
    let cap_unit = match cap.name("unit") {
        None => "m",
        Some(x) => x.as_str()
    };

    /*
     * Convert value to number(u64)
     */
    let value = cap_val.to_string().parse::<u32>().unwrap();

    if value < 1 {
        Err("Value is smallter than 1")?
    }

    /*
     * Calculate values
     */
    if &cap_unit == &"m" {
        Ok(value)
    } else if &cap_unit == &"h" {
        Ok(value * 60)
    } else if &cap_unit == &"d" {
        Ok(value * 60 * 24)
    } else {
        Ok(value)
    }
}

pub fn read_password_from_stdin() -> String {
    print!("[+] Enter password: ");
    io::stdout().flush().unwrap();
    let mut password = String::new();
    io::stdin().read_line(&mut password).expect("Failed to read line.");
    password.truncate(password.len() - 1);

    return password;
}
