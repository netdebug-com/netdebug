use std::sync::Arc;

use tokio_postgres::Client;

/// Bend over backwards to create a tokio_postgres::Client mock because the
/// useless #%(%*&@*( didn't want to make the trait fully public.
///
/// See details at: https://github.com/sfackler/rust-postgres/issues/1119
///
///
/// Workaround: create an enum that wraps the client and fails if a mock

#[derive(Clone)]

pub enum MockableDbClient {
    Real { client: Arc<Client> },
    Mock,
}

impl MockableDbClient {
    /// Will panic if a Mock
    pub fn get_client(&self) -> Arc<Client> {
        self.try_get_client()
            .expect("Tried to access the DbClient when it was really a mock!?")
    }

    /// Will return None if a Mock
    pub fn try_get_client(&self) -> Option<Arc<Client>> {
        use MockableDbClient::*;
        match self {
            Real { client } => Some(client.clone()),
            Mock => None,
        }
    }

    pub fn new_mock() -> MockableDbClient {
        MockableDbClient::Mock
    }
}

impl From<Client> for MockableDbClient {
    fn from(value: Client) -> Self {
        MockableDbClient::Real {
            client: Arc::new(value),
        }
    }
}
