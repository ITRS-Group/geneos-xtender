use serde::Serialize;
use std::error::Error;
use std::fmt;
use std::str::FromStr;

const VARIABLE_RE: &str = r"\$([A-Z_0-9]+)\$";

type VariableName = String;
type VariableValue = Option<String>;

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
                VariableKind::Secret(v) => v.to_secret_string(),
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
    Found(VariableName, VariableValue),
    NotFound(VariableName),
}

#[derive(Debug)]
pub struct VariableLookupError;

impl Error for VariableLookupError {}

impl fmt::Display for VariableLookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Failed to lookup Variable")
    }
}

impl FromStr for Variable {
    type Err = VariableLookupError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = std::env::var(s);
        if let Ok(value) = value {
            Ok(Self::Found(s.to_string(), Some(value)))
        } else {
            Ok(Self::NotFound(s.to_string()))
        }
    }
}

impl Variable {
    pub fn to_public_string(&self) -> String {
        match self {
            Variable::Found(name, value) => format!("{}=\"{}\"", name, value.as_ref().unwrap()),
            Variable::NotFound(name) => name.clone(),
        }
    }

    pub fn to_secret_string(&self) -> String {
        match self {
            Variable::Found(name, _) => format!("{}=***", name),
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
    pub new_string: Option<String>,
    pub variables_found: Option<Variables>,
    pub variables_not_found: Option<Variables>,
}

#[derive(Debug)]
pub enum VariableStringParseError {
    RegexError,
    VariableError(Box<dyn Error>),
}

impl Error for VariableStringParseError {}

impl fmt::Display for VariableStringParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableStringParseError::RegexError => {
                write!(f, "Failed to compile VariableString Regex")
            }
            VariableStringParseError::VariableError(err) => write!(f, "Variable error: {}", err),
        }
    }
}

impl From<regex::Error> for VariableStringParseError {
    fn from(_: regex::Error) -> Self {
        VariableStringParseError::RegexError
    }
}

impl From<VariableLookupError> for VariableStringParseError {
    fn from(err: VariableLookupError) -> Self {
        VariableStringParseError::VariableError(Box::new(err))
    }
}

impl FromStr for VariableString {
    type Err = VariableStringParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let variable_re = regex::Regex::new(VARIABLE_RE)?;
        let variable_names = variable_re
            .captures_iter(s)
            .filter_map(|c| c.get(1).map(|m| m.as_str().to_string()))
            .collect::<Vec<VariableName>>();

        let mut new_string = s.to_string();
        let mut found_variables = Variables::new();
        let mut missing_variables = Variables::new();

        if !variable_names.is_empty() {
            for variable_name in &variable_names {
                let variable = Variable::from_str(variable_name)?;

                match variable {
                    Variable::Found(name, value)
                        if value.as_ref().is_some_and(|x| x.starts_with("+encs+")) =>
                    // TODO: Is this what I want to do or do I want to replace the value with ***?
                    {
                        new_string =
                            new_string.replace(&format!("${}$", name), value.as_ref().unwrap());
                        found_variables.push(VariableKind::Secret(Variable::Found(
                            name.to_string(),
                            value,
                        )));
                    }
                    Variable::Found(name, value) => {
                        new_string =
                            new_string.replace(&format!("${}$", name), value.as_ref().unwrap());
                        found_variables.push(VariableKind::Public(Variable::Found(
                            name.to_string(),
                            value,
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
            new_string: Some(new_string),
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
