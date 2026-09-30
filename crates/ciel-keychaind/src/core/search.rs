//! ============================================================================
//! ciel-keychaind - Secret Search & Attribute Matching Engine
//!
//! Implements attribute-based item lookup according to the FreeDesktop Secret
//! Service specification:
//! - Exact string equality matching for key-value attribute pairs.
//! - Conjunctive evaluation: an item matches if and only if ALL specified
//!   query attributes exist on the item with identical values.
//! - An empty attribute query matches all items within the queried scope.
//!
//! ============================================================================

use std::collections::HashMap;

/// Attribute filter evaluator for Secret Service items.
#[derive(Debug, Clone)]
pub struct AttributeFilter<'a> {
    query: &'a HashMap<String, String>,
}

impl<'a> AttributeFilter<'a> {
    /// Creates a new filter wrapping a client's search attributes.
    pub fn new(query: &'a HashMap<String, String>) -> Self {
        Self { query }
    }

    /// Evaluates whether a candidate item's attributes satisfy the query filter.
    ///
    /// According to the FreeDesktop Secret Service specification:
    /// "Each attribute in the attributes dictionary must match an attribute on the item."
    #[inline]
    pub fn matches(&self, item_attributes: &HashMap<String, String>) -> bool {
        if self.query.is_empty() {
            return true;
        }

        for (key, expected_val) in self.query {
            match item_attributes.get(key) {
                Some(actual_val) if actual_val == expected_val => continue,
                _ => return false,
            }
        }

        true
    }
}

/// Convenience function testing attribute match against an attribute map.
pub fn matches_attributes(
    query: &HashMap<String, String>,
    item_attributes: &HashMap<String, String>,
) -> bool {
    AttributeFilter::new(query).matches(item_attributes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_query_matches_all() {
        let query = HashMap::new();
        let mut item_attrs = HashMap::new();
        item_attrs.insert("user".into(), "alice".into());

        assert!(matches_attributes(&query, &item_attrs));
    }

    #[test]
    fn test_conjunctive_exact_match() {
        let mut query = HashMap::new();
        query.insert("protocol".into(), "https".into());
        query.insert("host".into(), "github.com".into());

        let mut matching_item = HashMap::new();
        matching_item.insert("protocol".into(), "https".into());
        matching_item.insert("host".into(), "github.com".into());
        matching_item.insert("username".into(), "octocat".into());

        assert!(matches_attributes(&query, &matching_item));

        let mut mismatch_item = HashMap::new();
        mismatch_item.insert("protocol".into(), "https".into());
        mismatch_item.insert("host".into(), "gitlab.com".into());

        assert!(!matches_attributes(&query, &mismatch_item));
    }
}
