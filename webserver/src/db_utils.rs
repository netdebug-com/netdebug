use std::collections::HashMap;

use chrono::{DateTime, Utc};
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tokio_postgres::{
    binary_copy::BinaryCopyOutRow,
    types::{FromSql, Type},
};

use crate::remotedb_client::RemoteDBClientError;

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeRangeQueryParams {
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
}

impl TimeRangeQueryParams {
    /// for desktop_connections
    pub fn to_sql_where(&self) -> String {
        self.to_sql_where_with_keys("start_tracking_time", "last_packet_time")
    }

    /// for other tables
    pub fn to_sql_where_with_keys(&self, start_key: &str, end_key: &str) -> String {
        let mut parts = Vec::new();
        // string formatting for SQL is save here, because we use
        if let Some(start) = self.start {
            // the timestamp will be well-formed since we are using DateTime
            parts.push(format!(
                "{} >= '{}'",
                start_key,
                start.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            ));
        }
        if let Some(end) = self.end {
            parts.push(format!(
                "{} < '{}'",
                end_key,
                end.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true)
            ));
        }
        if parts.is_empty() {
            "".to_owned()
        } else {
            format!("({})", parts.join(" AND "))
        }
    }
}

/// Keeps track column names, types, and a column name-to-index mapping to make
/// `COPY TO` queries easier. While regular SELECT results allow one to get a column
/// by its name, COPY OUT only supports numeric index. This calls allows us to use
/// names. In addition, we track the postgre types of columns which are needed when
/// reading COPY OUT results
#[derive(Debug)]
pub struct CopyOutQueryHelper {
    col_names: Vec<String>,
    col_types: Vec<Type>,
    col_to_idx: HashMap<String, usize>,
}

impl CopyOutQueryHelper {
    pub fn new(columns: Vec<(&str, Type)>) -> Self {
        let mut col_to_idx = HashMap::with_capacity(columns.len());
        let mut col_names = Vec::with_capacity(columns.len());
        let mut col_types = Vec::with_capacity(columns.len());
        for (idx, (name, typ)) in columns.iter().enumerate() {
            col_to_idx.insert(name.to_string(), idx);
            col_types.push(typ.clone());
            col_names.push(name.to_string());
        }
        // Make sure we have every column name only once
        assert_eq!(columns.len(), col_to_idx.len());
        CopyOutQueryHelper {
            col_names,
            col_types,
            col_to_idx,
        }
    }

    /// Wrapper function around `BinaryCopyOutRow::get` that allows us to use column names
    /// instead of column indicies
    pub fn get<'a, T>(&self, row: &'a BinaryCopyOutRow, col: &str) -> Result<T, RemoteDBClientError>
    where
        T: FromSql<'a>,
    {
        let idx = *self
            .col_to_idx
            .get(col)
            .ok_or(RemoteDBClientError::NoSuchColumn {
                col_name: col.to_string(),
            })?;
        Ok(row.try_get(idx)?)
    }

    pub fn columns_names(&self) -> String {
        self.col_names.iter().join(", ")
    }

    pub fn col_types(&self) -> &[Type] {
        &self.col_types
    }
}

/// Take a list of terms for a SQL `WHERE` clause,
/// `AND` the terms together. If the result is non empty,
/// prepend `WHERE`.
pub fn make_where_clause(terms: &[&str]) -> String {
    let mut where_clause: String = terms.iter().filter(|x| !x.is_empty()).join(") AND (");
    if !where_clause.is_empty() {
        where_clause.insert_str(0, "WHERE (");
        where_clause += ")";
    }
    where_clause
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_make_where_clause() {
        assert_eq!(make_where_clause(&[]), "");
        assert_eq!(make_where_clause(&[""]), "");
        assert_eq!(make_where_clause(&["", ""]), "");
        assert_eq!(make_where_clause(&["foo"]), "WHERE (foo)");
        assert_eq!(
            make_where_clause(&["foo", "", "bar"]),
            "WHERE (foo) AND (bar)"
        );
        assert_eq!(
            make_where_clause(&["foo", "", "(bar)"]),
            "WHERE (foo) AND ((bar))"
        );
    }
}
