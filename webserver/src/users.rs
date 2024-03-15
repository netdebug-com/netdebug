use axum::async_trait;
use axum_login::{AuthUser, AuthnBackend, UserId};
use clerk_rs::{
    apis::{
        jwks_api::{Jwks, JwksModel},
        users_api::{GetUserError, GetUserListError, User},
        Error,
    },
    clerk::Clerk,
    validators::actix::ClerkJwt,
    ClerkConfiguration,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, str::FromStr, sync::Arc};
use thiserror::Error as ThisError;
use tokio_postgres::Client;

use crate::{
    remotedb_client::{RemoteDBClient, RemoteDBClientError},
    secrets_db::Secrets,
};

/// The local state for a NetDebug users; TODO add more state!
/// Clerk.com handles all of the authn for us but we still need
/// to keep our own local state about a user, e.g., what company they're from
#[allow(unused)] // TODO: remove!
#[derive(Clone)]
pub struct NetDebugUser {
    /// The UserId we use internally is exactly the clerk_user.id string
    pub user_id: String,
    /// A unique ID for the company the user is in.  If people have multiple companies,
    /// for now use multiple accounts
    pub organization_id: i64,
    /// A unique session key which is a hash of the user_id and the random seed
    pub session_key: Vec<u8>,
    // TODO : put in more state
}

impl std::fmt::Debug for NetDebugUser {
    /// Manually implement debug so that people do not accidentally log/print
    /// the session key.  Session keys might be short lived or long lived and
    /// the long lived ones are equivalent to a plaintext password.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // every field except for session_key
        f.debug_struct("NetDebugUser")
            .field("user_id", &self.user_id)
            .field("organization_id", &self.organization_id)
            .finish()
    }
}
impl NetDebugUser {
    pub fn make_session_key(user_id: &String, random_salt: &String) -> Vec<u8> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(user_id);
        hasher.update(random_salt);
        hasher.finalize().as_slice().to_owned()
    }

    /// Translate a User as defined by Clerk.com into our own internal
    /// state structure.  This should only be done after validating the
    /// user, e.g., by calling [UserServiceData::get_user_from_clerk_jwt()]
    async fn from_validated_clerk_user(
        clerk_user: &clerk_rs::models::User,
        random_salt: &String,
        client: &Arc<Client>,
    ) -> Result<Option<NetDebugUser>, UserAuthError> {
        match &clerk_user.id {
            Some(user_id) => {
                let session_key = NetDebugUser::make_session_key(user_id, random_salt);
                let organization = NetDebugUser::lookup_organization_id(user_id, client).await?;
                Ok(Some(NetDebugUser {
                    user_id: user_id.clone(),
                    organization_id: organization,
                    session_key,
                }))
            }
            None => Ok(None), // AFAICT, this should never happen but if it does, just return None="no user"
        }
    }

    /// Query the backend database to lookup this user's organization id
    /// TODO: expand this to be "lookup all of the things that only the backend DB has"
    async fn lookup_organization_id(
        user_id: &str,
        client: &Arc<Client>,
    ) -> Result<i64, UserAuthError> {
        let row = client
            .query_one(
                &format!(
                    "SELECT primary_email, organization, name FROM {} WHERE clerk_id = $1",
                    crate::remotedb_client::USERS_TABLE_NAME
                ),
                &[&user_id],
            )
            .await?;
        let organization_id = row.get::<_, i64>(1);
        // TODO: get and return more user data
        Ok(organization_id)
    }
}

/// Translation layer to tell Axum how to get our user's IDs and session auth token
impl AuthUser for NetDebugUser {
    type Id = String; // how we uniquely ID a user

    // Tell Axum how to get a unique id for the users
    fn id(&self) -> Self::Id {
        self.user_id.clone()
    }

    // Tell Axum how to get a unique session key for the user
    fn session_auth_hash(&self) -> &[u8] {
        self.session_key.as_slice()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthCredentials {
    pub clerk_jwt: String,
}
pub type AuthSession = axum_login::AuthSession<NetDebugUserBackend>;

#[derive(Clone)]
pub struct NetDebugUserBackend {
    /// A wrapper around our Clerk.com state
    user_service: UserService,
    /// Some random data to ensure our session_keys are not guessable
    /// NOTE: we don't presist or share this state so users will have
    /// to re-auth if the server reboots or going between servers
    ///
    /// TODO: persist the state :-)
    random_salt: String,
    /// read-only data-base client
    client: Arc<Client>,
}

impl NetDebugUserBackend {
    pub async fn new(
        user_service: UserService,
        secrets: &Secrets,
    ) -> Result<NetDebugUserBackend, RemoteDBClientError> {
        use rand::{distributions::Alphanumeric, Rng};
        // Create a 64-character long random string
        let random_salt = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();
        let client = Arc::new(RemoteDBClient::make_read_only_client(secrets).await?);
        Ok(NetDebugUserBackend {
            user_service,
            random_salt,
            client,
        })
    }
}

#[async_trait]
impl AuthnBackend for NetDebugUserBackend {
    #[doc = r" Authenticating user type."]
    type User = NetDebugUser;

    #[doc = r" Credential type used for authentication."]
    type Credentials = AuthCredentials;

    #[doc = r" An error which can occur during authentication and authorization."]
    type Error = UserAuthError;

    #[doc = r" Authenticates the given credentials with the backend."]
    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        match self
            .user_service
            .get_user_from_clerk_jwt(&creds.clerk_jwt)
            .await?
        {
            Some(clerk_user) => {
                NetDebugUser::from_validated_clerk_user(
                    &clerk_user,
                    &self.random_salt,
                    &self.client,
                )
                .await
            }
            None => Err(UserAuthError::UserNotFound {
                jwt: creds.clerk_jwt,
            }),
        }
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        // our user_id is a clerk id, so look it up in the clerk service
        let clerk_user = self.user_service.get_user(user_id).await?;
        NetDebugUser::from_validated_clerk_user(&clerk_user, &self.random_salt, &self.client).await
    }
}

/// Wrapper around the UserServiceData so we can create a shared instance
pub type UserService = Arc<UserServiceData>;

#[derive(ThisError, Debug)]
pub enum UserAuthError {
    #[error("Failed to validate JWT")]
    FailedToValidateJwt(#[from] jsonwebtoken::errors::Error),
    #[error("Api to Clerk Failed")]
    ClerkApiFailed(#[from] Error<GetUserError>),
    #[error("No public key matching KeyId {0}")]
    PublicKeyNotFound(String),
    #[error("There is no KeyId ('kid') in the JWT header!?")]
    JwtHeaderNoKeyId,
    #[error("Expected Algorithm {expected:?} but found {found:?}")]
    MisMatchedAlgorithms {
        expected: Algorithm,
        found: Algorithm,
    },
    #[error("Clerk could not find user matching JWT {jwt}")]
    UserNotFound { jwt: String },
    #[error("Error on backend DB lookup {0}")]
    BackendDbError(#[from] tokio_postgres::Error),
}

/// Abstract away some of the UserService details... but not that much
/// Currently quite tied to Clerk.com...
#[derive(Clone)]
pub struct UserServiceData {
    /// A wrappper around the auth and REST APIs to clerk
    client: Arc<Clerk>,
    /// A cached list of the Clerk public keys
    jwks_models: Arc<JwksModel>,
}

impl UserServiceData {
    /// service_secret is our auth to the backend service, e.g., Clerk's CLERK_SECRET_KEY
    /// NOTE: the "pk_test_XXX" testing key might be ok to check in (maybe?) but the
    ///   "pk_live_XXX" key is NOT!
    pub async fn new(service_secret: String) -> UserServiceData {
        let config = ClerkConfiguration::new(None, None, Some(service_secret), None);
        let client = Arc::new(Clerk::new(config.clone()));
        // TODO: decide if we want to/can cache the JWT models; still not super sure what they are
        let jwks_models = Arc::new(Jwks::get_jwks(&client).await.unwrap());
        UserServiceData {
            client,
            jwks_models,
        }
    }

    pub async fn new_locked(service_secret: String) -> UserService {
        Arc::new(UserServiceData::new(service_secret).await)
    }

    pub async fn list_users(&self) -> Result<Vec<clerk_rs::models::User>, Error<GetUserListError>> {
        User::get_user_list(
            &self.client,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .await
    }

    /// This is the "user_XXXXXXX" string in the sub of the JWT token from Clerk.com
    /// NOTE: Clerk can (will automatically?) merge accounts different auth providers
    pub async fn get_user(
        &self,
        user_id: &str,
    ) -> Result<clerk_rs::models::User, Error<GetUserError>> {
        User::get_user(&self.client, user_id).await
    }

    /// Parse the JWT and if it's valid, extract the 'sub' id and use that to lookup
    /// in Clerk.com's DB
    pub async fn get_user_from_clerk_jwt(
        &self,
        jwt: &str,
    ) -> Result<Option<clerk_rs::models::User>, UserAuthError> {
        // TODO: remove the unwrap()s! and return a joined error code
        // TODO: need to write custom validator - clerk_rs has a validator for Actix but that's not what we want
        let jwt = self.validate_clerk_jwt(jwt)?;
        let user_id = jwt.sub; // With Clerk's JWT, the 'sub' is the user_id
        let user = self.get_user(&user_id).await?;
        Ok(Some(user))
    }

    /// Parse and Validate the JWT from Clerk
    /// Use the jsonwebtoken crate to do the heavily validation lifting
    /// Following the examples from https://github.com/Keats/jsonwebtoken/blob/master/examples/validation.rs
    fn validate_clerk_jwt(&self, jwt: &str) -> Result<ClerkJwt, UserAuthError> {
        // Step #1: Parse just the header JWT without verification so we can get the key-id 'kid'
        let header = jsonwebtoken::decode_header(jwt)?;
        let kid = match header.kid {
            Some(kid) => kid,
            None => return Err(UserAuthError::JwtHeaderNoKeyId),
        };
        // Step #2: Find the public key that matches the signature key
        let pub_key = match self.jwks_models.keys.iter().find(|k| k.kid == kid) {
            Some(key) => key,
            None => return Err(UserAuthError::PublicKeyNotFound(kid)),
        };
        // Step #3: Decode the whole thing and validate the key
        let pub_key_alg = Algorithm::from_str(&pub_key.alg)?;
        if header.alg != pub_key_alg {
            return Err(UserAuthError::MisMatchedAlgorithms {
                found: header.alg,
                expected: pub_key_alg,
            });
        }
        let validation = Validation::new(Algorithm::RS256);
        let decoding_key = DecodingKey::from_rsa_components(&pub_key.n, &pub_key.e)?;
        // we can apparently validate the claims at the same time, but I don't think we need to
        // This call validates both the crypto and the timestamps, AFAICT
        let parsed_jwt = jsonwebtoken::decode::<ClerkJwt>(jwt, &decoding_key, &validation)?;
        Ok(parsed_jwt.claims)
    }
}

/// Mock version of [NetDebugAuthBackend]
#[derive(Debug, Clone, Default)]
pub struct MockAuthBackend {
    pub user_db: HashMap<String, NetDebugUser>,
}

impl MockAuthBackend {
    #[allow(unused)] // odd that this complains that it's unused but also 'pub'
    pub fn add_user(&mut self, user_id: String, user: NetDebugUser) {
        self.user_db.insert(user_id, user);
    }
}

#[async_trait]
impl AuthnBackend for MockAuthBackend {
    type User = NetDebugUser;
    type Credentials = AuthCredentials;
    type Error = UserAuthError;

    async fn authenticate(
        &self,
        creds: Self::Credentials,
    ) -> Result<Option<Self::User>, Self::Error> {
        // fake auth - assume the jwt is the user name and if it exists in our db, just accept it
        Ok(self.user_db.get(&creds.clerk_jwt).cloned())
    }

    async fn get_user(&self, user_id: &UserId<Self>) -> Result<Option<Self::User>, Self::Error> {
        Ok(self.user_db.get(user_id).cloned())
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    // I *think* this is ok to check in; it's a "secret" but only for our
    // dev/testing environment so I think all someone could do with this is add/delete/DoS
    // our testing instance... which given that the repo is private and this should never
    // leak, I'm ok with that...
    const TESTING_KEY: &str = "sk_test_sYZlSJcMcbrwt1N5SK3HaxOrI2ntmkW0aNcSEcEGkl";

    /// Can we connect to the auth and get a list of users?
    #[tokio::test]
    async fn test_get_users() {
        let user_service = UserServiceData::new(TESTING_KEY.to_string()).await;
        for user in user_service.list_users().await.unwrap() {
            println!("User: {:#?}", user);
        }
    }

    /// This test will only work if Rob has logged into Clerk.com - which he has!
    #[tokio::test]
    async fn test_get_user() {
        let user_service = UserServiceData::new(TESTING_KEY.to_string()).await;
        let rob = "user_2d1N4hIK6SPh90QI7W2YrGpgHRD";
        let user = user_service.get_user(rob).await.unwrap();
        let emails = user.email_addresses.unwrap();
        let email_address = emails.first().unwrap();
        assert_eq!(email_address.email_address, "rob.sherwood@netdebug.com",);
    }

    #[tokio::test]
    async fn test_validate_expired_jwt() {
        // sigh; can't cache a valid JWT without it expiring on us,
        // Doesn't seem easy to generate a new JWT without login info
        // but we can at least make sure an // expired one doesn't validate
        let rob_jwt = "eyJhbGciOiJSUzI1NiIsImNhdCI6ImNsX0I3ZDRQRDExMUFBQSIsImtpZCI6Imluc18yZDFJRFF2SU5yNWNXRXVwOElHY2JrWFlUN1UiLCJ0eXAiOiJKV1QifQ.eyJhenAiOiJodHRwOi8vbG9jYWxob3N0OjUxNzMiLCJleHAiOjE3MDkzMTYzODEsImlhdCI6MTcwOTMxNjMyMSwiaXNzIjoiaHR0cHM6Ly9raW5kLXJhcHRvci0xOS5jbGVyay5hY2NvdW50cy5kZXYiLCJuYmYiOjE3MDkzMTYzMTEsInNpZCI6InNlc3NfMmQ0NDZ2RGNjT000aW91Qm5TcGtaTFdicGtUIiwic3ViIjoidXNlcl8yZDFONGhJSzZTUGg5MFFJN1cyWXJHcGdIUkQifQ.xNSN7_c0Gh4JYQWSVQbSMn4obdMprep4h1rlTj9VcwqXyiXo8qTy5EsbsWZOY48bZ8jK3HgC7i4sPX76NrT_MMBF5qIZc3oIkgc9rcdPEbUksOJhHyaPX64d9MxuYnylYb_QRxISCZ5mWM2khfuXTzItCWpp9MDnpT8G1nucQhCa-R6pP80-TAK7noyTQ_TuqNUWyfDqVluh5_wo63-M7R3qpdmPMPqlxHopL2iYGtdHlViBf8dUDHN_d-9G7WGx7Ea4CEThZ-btDhCEiEvSwe0j0DzCU6kKu-o17vqroPIIwnP-AZl-prZmKAw80BckvnwEkqwwDstg-1dGKYNe7Q";
        let user_service = UserServiceData::new(TESTING_KEY.to_string()).await;
        match user_service.validate_clerk_jwt(rob_jwt) {
            Ok(_) => panic!("Expired JWT actually validated!?"),
            Err(e) => {
                use jsonwebtoken::errors::ErrorKind::*;
                match e {
                    UserAuthError::FailedToValidateJwt(e2) => match e2.kind() {
                        ExpiredSignature => (), // correct!
                        _wut => panic!("Wrong Auth error type - expected expired: {:?}", _wut),
                    },
                    _wut => panic!("Wrong validation error: {}", _wut),
                }
            }
        }
    }
}
