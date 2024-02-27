use clerk_rs::{
    apis::{
        jwks_api::{Jwks, JwksKey, JwksModel},
        users_api::{GetUserError, GetUserListError, User},
        Error,
    },
    clerk::Clerk,
    validators::actix::ClerkJwt,
    ClerkConfiguration,
};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use std::{str::FromStr, sync::Arc};
use thiserror::Error as ThisError;
use tokio::sync::Mutex;

/// Wrapper around the UserServiceData so we can create a shared instance
pub type UserService = Arc<Mutex<UserServiceData>>;

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
}

/// Abstract away some of the UserService details... but not that much
/// Currently quite tied to Clerk.com...
pub struct UserServiceData {
    /// A wrappper around the auth and REST APIs to clerk
    client: Clerk,
    /// A cached list of the Clerk public keys
    jwks_models: JwksModel,
    /// The clerk config, needed to create a new client
    config: ClerkConfiguration,
}

impl Clone for UserServiceData {
    // manually implement Clone b/c clerk_rs::Clerk doesn't do it
    fn clone(&self) -> Self {
        // sigh, neither client or jwks_models impl Clone
        let client = Clerk::new(self.config.clone());
        let keys = self
            .jwks_models
            .keys
            .iter()
            .map(|k| JwksKey {
                use_key: k.use_key.clone(),
                kty: k.kty.clone(),
                kid: k.kid.clone(),
                alg: k.alg.clone(),
                n: k.n.clone(),
                e: k.e.clone(),
            })
            .collect::<Vec<JwksKey>>();
        Self {
            client,
            jwks_models: JwksModel { keys },
            config: self.config.clone(),
        }
    }
}

impl UserServiceData {
    /// service_secret is our auth to the backend service, e.g., Clerk's CLERK_SECRET_KEY
    /// NOTE: the "pk_test_XXX" testing key might be ok to check in (maybe?) but the
    ///   "pk_live_XXX" key is NOT!
    pub async fn new(service_secret: String) -> UserServiceData {
        let config = ClerkConfiguration::new(None, None, Some(service_secret), None);
        let client = Clerk::new(config.clone());
        // TODO: decide if we want to/can cache the JWT models; still not super sure what they are
        let jwks_models = Jwks::get_jwks(&client).await.unwrap();
        UserServiceData {
            client,
            jwks_models,
            config,
        }
    }

    pub async fn new_locked(service_secret: String) -> UserService {
        Arc::new(Mutex::new(UserServiceData::new(service_secret).await))
    }

    pub async fn list_users(
        &mut self,
    ) -> Result<Vec<clerk_rs::models::User>, Error<GetUserListError>> {
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
        &mut self,
        user_id: &str,
    ) -> Result<clerk_rs::models::User, Error<GetUserError>> {
        User::get_user(&self.client, user_id).await
    }

    /// Parse the JWT and if it's valid, extract the 'sub' id and use that to lookup
    /// in Clerk.com's DB
    pub async fn get_user_from_clerk_jwt(
        &mut self,
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

#[cfg(test)]
mod test {
    use super::*;

    // I *think* this is ok to check in; it's a "secret" but only for our
    // dev/testing environment so I think all someone could do with this is add/delete/DoS
    // our testing instance... which given that the repo is private and this should never
    // leak, I'm ok with that...
    const TESTING_KEY: &str = "sk_test_sYZlSJcMcbrwt1N5SK3HaxOrI2ntmkW0aNcSEcEGkl";

    /// Can we connect to the auth and get a list of users?
    #[tokio::test]
    async fn test_get_users() {
        let mut user_service = UserServiceData::new(TESTING_KEY.to_string()).await;
        for user in user_service.list_users().await.unwrap() {
            println!("User: {:#?}", user);
        }
    }

    /// This test will only work if Rob has logged into Clerk.com - which he has!
    #[tokio::test]
    async fn test_get_user() {
        let mut user_service = UserServiceData::new(TESTING_KEY.to_string()).await;
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
