const RANGE_RE: &str = r"!!(A|B):([0-9]+)\.\.([0-9]+)!!";

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Range {
    pub name: String,
    pub start: i32,
    pub end: i32,
}

pub type Ranges = Vec<Range>;
pub trait RangesExt {
    fn from_str(s: &str) -> Self;
}

impl Range {
    pub fn new(name: &str, start: i32, end: i32) -> Self {
        Self {
            name: name.to_string(),
            start,
            end,
        }
    }
}

// fn contains_named_range(s: &str) -> bool {
//     let range_re = regex::Regex::new(RANGE_RE).unwrap();
//     range_re.is_match(s)
// }

// fn contains_multiple_ranges(s: &str) -> bool {
//     let range_re = regex::Regex::new(RANGE_RE).unwrap();
//     let mut ranges = Vec::new();

//     for c in range_re.captures_iter(s) {
//         let name = c.get(1).unwrap().as_str();
//         let start = c.get(2).unwrap().as_str().parse::<i32>().unwrap();
//         let end = c.get(3).unwrap().as_str().parse::<i32>().unwrap();
//         ranges.push((name, start, end));
//     }

//     if ranges.is_empty() || ranges.len() == 1 {
//         return false;
//     }

//     ranges.sort();
//     ranges.dedup();

//     ranges.len() > 1
// }

impl RangesExt for Ranges {
    fn from_str(s: &str) -> Ranges {
        let range_re = regex::Regex::new(RANGE_RE).unwrap();
        let mut ranges = Ranges::new();

        for c in range_re.captures_iter(s) {
            let name = c.get(1).unwrap().as_str().to_string();
            let start = c.get(2).unwrap().as_str().parse::<i32>().unwrap();
            let end = c.get(3).unwrap().as_str().parse::<i32>().unwrap();
            ranges.push(Range::new(&name, start, end));
        }

        ranges
    }
}

#[cfg(test)]
mod range_test {
    use super::*;
    use pretty_assertions::assert_eq;
    #[test]
    fn test_ranges_from_str() {
        assert_eq!(Ranges::from_str(""), vec![]);
        assert_eq!(Ranges::from_str("!!A:1..2!!"), vec![Range::new("A", 1, 2)]);
        assert_eq!(Ranges::from_str("!!B:3..4!!"), vec![Range::new("B", 3, 4)]);
        assert_eq!(
            Ranges::from_str("!!A:1..2!! !!B:3..4!!"),
            vec![Range::new("A", 1, 2), Range::new("B", 3, 4)]
        );
        // Only A or B is allowed.
        assert_eq!(
            Ranges::from_str("!!A:1..2!! !!B:3..4!! !!C:5..6!!"),
            vec![Range::new("A", 1, 2), Range::new("B", 3, 4)]
        );
    }
}
