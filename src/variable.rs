use hex::decode;
use lazy_static::lazy_static;
use log::debug;
use openssl::symm::{Cipher, Crypter, Mode};
use serde::Serialize;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use std::sync::RwLock;

lazy_static! {
    pub static ref KEY_FILE: RwLock<Option<KeyFile>> = RwLock::new(None);
}

const VARIABLE_RE: &str = r"\$([A-Z_0-9]+)\$";

type VariableName = String;
type VariableValue = Option<String>;
type SecretVariableValue = Option<String>;

pub type Variables = Vec<VariableKind>;
pub trait VariablesExt {
    fn to_string(&self) -> String;
}

impl VariablesExt for Variables {
    fn to_string(&self) -> String {
        let strings = self
            .iter()
            .map(|v| match v {
                VariableKind::Public(v) => v.to_public_string(),
                VariableKind::Secret(v) => v.to_hidden_string(),
            })
            .collect::<Vec<String>>();

        if strings.is_empty() {
            return String::new();
        }

        strings.join(",")
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum Variable {
    Found(VariableName, VariableValue, SecretVariableValue),
    NotFound(VariableName),
}

#[derive(Debug)]
pub enum VariableError {
    RegexError,
    ParseError(Box<dyn Error>),
    EnvVarError(VariableName),
    DecryptionError(openssl::error::ErrorStack),
    NoKeyFileError(VariableName),
}

impl Error for VariableError {}

impl From<regex::Error> for VariableError {
    fn from(_: regex::Error) -> Self {
        VariableError::RegexError
    }
}

impl From<openssl::error::ErrorStack> for VariableError {
    fn from(_: openssl::error::ErrorStack) -> Self {
        VariableError::DecryptionError(openssl::error::ErrorStack::get())
    }
}

impl fmt::Display for VariableError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableError::EnvVarError(variable_name) => {
                write!(f, "Failed to lookup variable \"{}\"", variable_name)
            }
            VariableError::NoKeyFileError(variable_name) => {
                write!(
                    f,
                    "The variable \"{}\" is encrypted but no KeyFile was provided",
                    variable_name
                )
            }
            VariableError::DecryptionError(err) => {
                write!(f, "Failed to decrypt variable with error: {}", err)
            }
            VariableError::RegexError => {
                write!(f, "Failed to compile VariableString Regex")
            }
            VariableError::ParseError(err) => write!(f, "Parse error: {}", err),
        }
    }
}

impl FromStr for Variable {
    type Err = VariableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let key_file = KEY_FILE.read().unwrap();

        let env_var_value = std::env::var(s);

        if let Ok(value) = env_var_value {
            if potentially_encrypted(&value) {
                if let Some(ref key) = *key_file {
                    let decrypted_value = decrypt_str(&value, key)?;

                    Ok(Self::Found(
                        s.to_string(),
                        Some(value.clone()),
                        Some(decrypted_value),
                    ))
                } else {
                    Err(VariableError::NoKeyFileError(s.to_string()))
                }
            } else {
                Ok(Self::Found(s.to_string(), Some(value.clone()), None))
            }
        } else {
            Ok(Self::NotFound(s.to_string()))
        }
    }
}

impl Variable {
    pub fn to_public_string(&self) -> String {
        match self {
            Variable::Found(name, value, _secret_value) => {
                format!("{}=\"{}\"", name, value.as_ref().unwrap())
            }
            Variable::NotFound(name) => name.clone(),
        }
    }

    pub fn to_hidden_string(&self) -> String {
        match self {
            Variable::Found(name, _value, _secret_value) => format!("{}=***", name),
            Variable::NotFound(name) => name.clone(),
        }
    }

    pub fn to_secret_string(&self) -> String {
        match self {
            Variable::Found(name, _value, secret_value) => {
                format!("{}={}", name, secret_value.clone().unwrap())
            }
            Variable::NotFound(name) => name.clone(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum VariableKind {
    Public(Variable),
    Secret(Variable),
}

#[derive(Debug, Default)]
pub struct VariableString {
    pub original_string: String,
    clear_string: Option<String>,
    pub obfuscated_string: Option<String>,
    pub variables_found: Option<Variables>,
    pub variables_not_found: Option<Variables>,
}

impl VariableString {
    pub fn clear_string(&self) -> Option<String> {
        self.clear_string.clone()
    }
}

impl FromStr for VariableString {
    type Err = VariableError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let variable_re = regex::Regex::new(VARIABLE_RE)?;
        let variable_names = variable_re
            .captures_iter(s)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect::<Vec<VariableName>>();

        let mut clear_string: VariableName = s.to_string();
        let mut obfuscated_string: VariableValue = None;
        let mut found_variables = Variables::new();
        let mut missing_variables = Variables::new();

        if !variable_names.is_empty() {
            for variable_name in &variable_names {
                let variable = Variable::from_str(variable_name)?;
                match variable {
                    Variable::Found(name, value, secret_value)
                        if secret_value.as_ref().is_some() =>
                    {
                        obfuscated_string = match obfuscated_string {
                            None => Some(clear_string.replace(&format!("${}$", name), "***")),
                            Some(s) => Some(s.replace(&format!("${}$", name), "***")),
                        };
                        clear_string = clear_string
                            .replace(&format!("${}$", name), &secret_value.clone().unwrap());
                        found_variables.push(VariableKind::Secret(Variable::Found(
                            name.to_string(),
                            value,
                            secret_value,
                        )));
                    }
                    Variable::Found(name, value, secret_value) => {
                        clear_string =
                            clear_string.replace(&format!("${}$", name), value.as_ref().unwrap());
                        found_variables.push(VariableKind::Public(Variable::Found(
                            name.to_string(),
                            value,
                            secret_value,
                        )));
                    }
                    Variable::NotFound(name) => {
                        missing_variables
                            .push(VariableKind::Public(Variable::NotFound(name.to_string())));
                    }
                }
            }

            found_variables.sort();
            found_variables.dedup();

            missing_variables.sort();
            missing_variables.dedup();
        }

        Ok(Self {
            original_string: s.to_string(),
            clear_string: Some(clear_string),
            obfuscated_string,
            variables_found: {
                if found_variables.is_empty() {
                    None
                } else {
                    Some(found_variables)
                }
            },
            variables_not_found: {
                if missing_variables.is_empty() {
                    None
                } else {
                    Some(missing_variables)
                }
            },
        })
    }
}

#[derive(Debug)]
pub struct KeyFile {
    _salt: String,
    key: String,
    iv: String,
}

// Example key file content:
// salt=89A6A795C9CCECB5
// key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
// iv =472A3557ADDD2525AD4E555738636A67

#[derive(Debug)]
pub enum KeyFileParseError {
    InvalidLine(String),
    MissingKey,
    MissingSalt,
    MissingIv,
    FileTooLong(usize),
}

impl fmt::Display for KeyFileParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyFileParseError::InvalidLine(line) => write!(f, "Invalid line: {}", line),
            KeyFileParseError::MissingKey => {
                write!(f, "Missing key, no line starting with \"key=\" found")
            }
            KeyFileParseError::MissingSalt => {
                write!(f, "Missing salt, no line starting with \"salt=\" found")
            }
            KeyFileParseError::MissingIv => {
                write!(f, "Missing iv, no line starting with \"iv =\" found")
            }
            KeyFileParseError::FileTooLong(length) => {
                write!(
                    f,
                    "Key file too long, expected 2-3 lines, {} lines found",
                    length
                )
            }
        }
    }
}

impl FromStr for KeyFile {
    type Err = KeyFileParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let number_of_lines = s.trim_end_matches('\n').lines().count();

        if number_of_lines > 3 {
            return Err(KeyFileParseError::FileTooLong(number_of_lines));
        }

        let mut salt = None;
        let mut key = None;
        let mut iv = None;

        for line in s.trim_end_matches('\n').lines() {
            if let Some(salt_val) = line.strip_prefix("salt=") {
                salt = Some(salt_val.to_string());
            } else if let Some(key_val) = line.strip_prefix("key=") {
                key = Some(key_val.to_string());
            } else if let Some(iv_val) = line.strip_prefix("iv =") {
                iv = Some(iv_val.to_string());
            } else {
                return Err(KeyFileParseError::InvalidLine(line.to_string()));
            }
        }

        if salt.is_none() {
            //return Err(KeyFileParseError::MissingSalt);
            debug!("The key file is missing the salt, this is not a problem.")
        }

        if key.is_none() {
            return Err(KeyFileParseError::MissingKey);
        }

        if iv.is_none() {
            return Err(KeyFileParseError::MissingIv);
        }

        Ok(Self {
            _salt: salt.unwrap_or_default(),
            key: key.unwrap(),
            iv: iv.unwrap(),
        })
    }
}

// I say potentially, because it's not a dead certain positive, only a dead sure negative.
fn potentially_encrypted(s: &str) -> bool {
    if !s.starts_with("+encs+") {
        return false;
    }

    let maybe_hex = &s[6..];
    maybe_hex.chars().all(|c| c.is_ascii_hexdigit())
}

fn decrypt_str(s: &str, k: &KeyFile) -> Result<String, openssl::error::ErrorStack> {
    let encrypted_data = decode(&s[6..]).unwrap();

    let cipher = Cipher::aes_256_cbc();
    let mut decrypter = Crypter::new(
        cipher,
        Mode::Decrypt,
        &hex::decode(&k.key).unwrap(),
        Some(&hex::decode(&k.iv).unwrap()),
    )
    .unwrap();
    let mut decrypted_data = vec![0; encrypted_data.len() + cipher.block_size()];
    let mut decrypted_length = decrypter
        .update(&encrypted_data, &mut decrypted_data)
        .unwrap();
    decrypted_length += decrypter
        .finalize(&mut decrypted_data[decrypted_length..])
        .unwrap();
    decrypted_data.truncate(decrypted_length);

    Ok(String::from_utf8(decrypted_data).unwrap())
}

#[cfg(test)]
mod variable_test {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_replace_variables_in_str() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        assert_eq!(
            &VariableString::from_str("hello")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello"
        );
        assert_eq!(
            &VariableString::from_str("hello FOO$")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello FOO$"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello $FOO"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello bar"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$ $BAZ$")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello bar qux"
        );
        assert_eq!(
            &VariableString::from_str("hello $FOO$ $BAZ$ $FOO$")
                .unwrap()
                .clear_string
                .unwrap(),
            "hello bar qux bar"
        );
    }

    #[test]
    fn test_replace_variables_in_str_missing_var() {
        std::env::set_var("FOO", "bar");
        std::env::set_var("BAZ", "qux");

        let r = VariableString::from_str("hello $FOO$ $MISSING$ $BAZ$");

        assert_eq!("hello bar $MISSING$ qux", r.unwrap().clear_string.unwrap());
    }

    #[test]
    fn test_valid_keyfile_from_str() {
        let valid_string = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67
"#;

        let valid_keyfile = KeyFile::from_str(valid_string).unwrap();

        assert_eq!(valid_keyfile._salt, "89A6A795C9CCECB5");
        assert_eq!(
            valid_keyfile.key,
            "26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC"
        );
        assert_eq!(valid_keyfile.iv, "472A3557ADDD2525AD4E555738636A67");
    }

    #[test]
    fn test_keyfile_from_str_missing_iv() {
        let short_string = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
"#;

        let result = KeyFile::from_str(short_string);

        assert!(result.is_err());
    }

    #[test]
    fn test_keyfile_from_str_missing_key() {
        let short_string = r#"salt=89A6A795C9CCECB5
iv =472A3557ADDD2525AD4E555738636A67
"#;

        let result = KeyFile::from_str(short_string);

        assert!(result.is_err());
    }

    #[test]
    fn test_keyfile_from_str_missing_salt() {
        let short_string = r#"key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67
"#;

        let result = KeyFile::from_str(short_string);

        // We don't care about a missing salt for now.
        assert!(result.is_ok());
    }

    #[test]
    fn test_too_long_keyfile_from_str() {
        let long_string = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67
foo=AAA123
"#;

        let result = KeyFile::from_str(long_string);

        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_line_in_keyfile_from_str() {
        let bad_string = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
foo=AAA123
"#;

        let result = KeyFile::from_str(bad_string);

        assert!(result.is_err());
    }

    #[test]
    fn test_potentially_encrypted_string_is_recognized() {
        let s = r"+encs+BCC9E963342C9CFEFB45093F3437A680";

        let result = potentially_encrypted(s);

        assert!(result);
    }

    #[test]
    fn test_definitely_not_encrypted_string_is_recognized() {
        let s = "foo";

        let result = potentially_encrypted(s);

        assert!(!result);
    }

    #[test]
    fn test_non_hex_string_is_recognized_as_not_potentially_encrypted() {
        let s = r"+encs+BCC9E963342C9CFEFB45093F3437A680ÅÄÖ";

        let result = potentially_encrypted(s);

        assert!(!result);
    }

    const ENCRYPTED_TEXT_1: &str = r"+encs+BCC9E963342C9CFEFB45093F3437A680";
    const ENCRYPTED_TEXT_2: &str = r"+encs+E245F3CCC5101CCEF28537908A427B13";
    const ENCRYPTED_TEXT_3: &str = r"+encs+C06214530622C38896D496587F5DF94AFC1A966F6A99D09A6CD2B74F857BE9A8E542F1498AA7065DFF8B9C271E07A8A0B2AB82BC9A0E51779465B322C49F45A43FAE745DF260A34913B9D914BD8CB3710C89F15B5AA17FD5C0748D86173FF479CEB26EB187DBBD23716F27490AFC3415C041347A3E39D222AAE1C40BF7F9895BC33BC0ED6677FBB58289A23CFECBD1AC90A43E0395383F18DD877B2C95A2C87A77C1BB3CF3171259C4E905EE7CC51C06E7B044B9193CE66F9B61BE81519AA7DDD2F159EEF4D2105F449FC10FB5D0580D60E965B4BC3B6547B136371C51A2BC5C90BA7336AEF5A2AAE2EAB6F11CA68B699E8A00300DE7BC6346669F8E76B7F54D05F68FA93156FCE30A43E0283828A02C733EC2434FD0B855157252BC7A6EAC8EE0235C3644FC0EA35D045100B4A2B8CA4242A1B4B29E95875F80D44068E5C82D776F83C62126448004D5C035047F8C0C0C1DE4DBBB64CE451898E5E39AFF95AA8AF8BE1AE503CAE3CCF86A615D573C3F8CA5FBCEE6C19207F1B0F25113FF35C4AB279D57F240B54D48873247030B10620A41CA541C02959B930FE1C5C1E33EB384537975BE86688D09EB83F98CC4D19548842DB603A3FC1FED9AF04FCB3D0AEE";

    const ORIGINAL_TEXT_1: &str = r"12345";
    const ORIGINAL_TEXT_2: &str = r"Lorem Ipsum";
    const ORIGINAL_TEXT_3: &str = r"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.";

    const KEY_FILE: &str = r#"salt=89A6A795C9CCECB5
key=26D6EDD53A0AFA8FA1AA3FBCD2FFF2A0BF4809A4E04511F629FC732C2A42A8FC
iv =472A3557ADDD2525AD4E555738636A67
"#;

    #[test]
    fn test_decrypt_str() {
        let kf = KeyFile::from_str(KEY_FILE).unwrap();

        let result_1 = decrypt_str(ENCRYPTED_TEXT_1, &kf);
        assert_eq!(result_1.unwrap(), ORIGINAL_TEXT_1.to_string());

        let result_2 = decrypt_str(ENCRYPTED_TEXT_2, &kf);
        assert_eq!(result_2.unwrap(), ORIGINAL_TEXT_2.to_string());

        let result_3 = decrypt_str(ENCRYPTED_TEXT_3, &kf);
        assert_eq!(result_3.unwrap(), ORIGINAL_TEXT_3.to_string());
    }
}
