//! # actix-web-jwt
//! This is a JWT token validation middleware for actix-web.
//! This middleware will validate the JWT token and forward the request to the next middleware.
//! If the token is invalid then it will return a 401 response.
//!
//! JWKS is used to validate the token. Application must periodically invoke the JWKS endpoint using the *CertInvoker* to get the latest cert.
//!
//!
//! # Documentation
//! * [Examples Repository](https://github.com/keaz/actix-web-jwt/examples)
//!
use std::{
    fmt::{self, Display},
    future::{ready, Ready},
    sync::Arc,
};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    error, Error, HttpResponse,
};
use futures_util::future::LocalBoxFuture;
use jsonwebtoken::{decode, decode_header, DecodingKey, Validation, TokenData};
use log::{debug, error, info, warn};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;

pub struct Jwt {
    cert_invoker: Arc<CertInvoker>,
    validator: Option<Arc<dyn JWTValidator>>,

}

///
/// This is use to validate the JWT token in a application specific way
/// 
pub trait JWTValidator  {

    ///
    /// Validate the token.
    /// Should now use any blocking operation
    /// 
    /// # Arguments
    /// * `toke_data` - The token data
    /// 
    /// # Return
    /// * `Result<(), JWTResponseError>` - If the token is valid then return Ok otherwise return Err
    /// 
    /// 
    fn validate(&self,toke_data:TokenData<Claims>) -> Result<(), JWTResponseError>;
    
} 



///
/// Use to crete a JWT middleware
///
impl Jwt {
    ///
    /// Creates a JWT from the CertInvoker
    ///
    pub fn from(cert_invoker: Arc<CertInvoker>,validator: Option<Arc<dyn JWTValidator>>) -> Self {
        Jwt { cert_invoker, validator }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Jwt
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = JwtMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(JwtMiddleware {
            service,
            cert_invoker: Arc::clone(&self.cert_invoker),
            validator: self.validator.clone(),
        }))
    }
}

///
/// JWT middleware for toke validation
///
pub struct JwtMiddleware<S> {
    service: S,
    cert_invoker: Arc<CertInvoker>,
    validator: Option<Arc<dyn JWTValidator>>,
}

const BEARER: &str = "Bearer ";

impl<S, B> Service<ServiceRequest> for JwtMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::error::Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let headers = req.headers();
        let jwt_token = headers
            .iter()
            .filter(|(header, _)| header.as_str() == "authorization")
            .map(|(_, value)| String::from(value.to_str().unwrap()))
            .collect::<Vec<String>>();

        let fut = self.service.call(req);
        let cert = Arc::clone(&self.cert_invoker.cert);
        let function = self.validator.clone();

        Box::pin(async move {
            if jwt_token.is_empty() {
                warn!("Missing JWT token");
                let x = actix_web::error::Error::from(JWTResponseError::missing_jwt());
                return Err(x);
            }

            let jwt_token = jwt_token.join("");

            if !jwt_token.starts_with(BEARER) {
                warn!("JWT is not started with Bearer");
                let x = actix_web::error::Error::from(JWTResponseError::invalid_jwt());
                return Err(x);
            }

            let jwt_token = jwt_token.replace(BEARER, "");
            let jwt_header = decode_header(&jwt_token);
            if jwt_header.is_err() {
                warn!("JWT header is invalid");
                let x = actix_web::error::Error::from(JWTResponseError::invalid_jwt());
                return Err(x);
            }
            let jwt_header = jwt_header.unwrap();
            let kid = jwt_header.kid.unwrap();

            let jwt_cert = cert.lock().await;
            let cert = jwt_cert.clone().unwrap(); // Cert should available at this point

            let key = cert.keys.iter().find(|key| key.kid == kid).unwrap();
            let de_key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str()).unwrap();
            let token = decode::<Claims>(&jwt_token, &de_key, &Validation::new(jwt_header.alg));

            match token {
                Ok(toke_data) => {
                    if let Some(function) = function {
                        let result: Result<_, _> = function.validate(toke_data);
                        if let Err(err) = result {
                            return Err(err.into())
                        }
                    }
                    Ok(fut.await?)
                },
                Err(err) => {
                    match err.kind() {
                        jsonwebtoken::errors::ErrorKind::InvalidSignature => return Err(invalid_invalid_signature()),
                        jsonwebtoken::errors::ErrorKind::ExpiredSignature => return Err(expired_jwt()),
                        jsonwebtoken::errors::ErrorKind::InvalidIssuer => return Err(invalid_invalid_iss()),
                        _ => {
                            warn!("JWT is invalid {:?}", err);
                            return Err(invalid_jwt())
                        },
                    }
                }
            }
        })
    }
}

fn invalid_jwt() -> actix_web::Error {
    return actix_web::error::Error::from(
        JWTResponseError::invalid_jwt(),
    )
}

fn expired_jwt() -> actix_web::Error {
    return actix_web::error::Error::from(
        JWTResponseError::expired_jwt(),
    )
}

fn invalid_invalid_signature() -> actix_web::Error {
    return actix_web::error::Error::from(
        JWTResponseError::invalid_invalid_signature(),
    )
}

fn invalid_invalid_iss() -> actix_web::Error {
    return actix_web::error::Error::from(
        JWTResponseError::invalid_invalid_issr(),
    )
}

async fn get_cert(cert_url: &String) -> Result<Cert, JWKSError> {
    debug!("Getting cert");
    let response = reqwest::get(cert_url).await;
    if response.is_err() {
        warn!("Error while getting cert");
        return Err(JWKSError::InvokingCertUrl(
            "Error while getting cert".to_string(),
        ));
    }
    let cert: Result<CertResponse, reqwest::Error> = response.unwrap().json().await;
    if cert.is_err() {
        warn!("Error while deserialize cert");
        return Err(JWKSError::ErrorDeserializingCert(format!(
            "Error while deserialize cert {:?}",
            cert.err().unwrap()
        )));
    }

    let keys = cert.unwrap().keys.iter().map(|key| {
        let de_key = DecodingKey::from_rsa_components(key.n.as_str(), key.e.as_str()).unwrap();
        Key::from(key.clone(), de_key)
    }).collect();
    
    Ok(Cert{keys})
}

///
/// This is use to invoke cert endpoint and store the cert in memory
///
pub struct CertInvoker {
    cert: Arc<Mutex<Option<Cert>>>,
    cert_url: String,
}

impl CertInvoker {
    ///
    /// Create a new CertInvoker form cert cert url
    /// # Arguments
    /// * `cert_url` - The cert url
    ///
    /// # Example
    /// ```
    /// use actix_web_jwt::CertInvoker;
    /// fn main() {
    ///     let cert_url = String::from("https://www.googleapis.com/oauth2/v3/certs");
    ///     let cert_invoker = CertInvoker::from(cert_url);
    /// }
    /// ```
    pub fn from(cert_url: String) -> Self {
        CertInvoker {
            cert: Arc::new(Mutex::new(None)),
            cert_url,
        }
    }

    ///
    /// Invoke the cert endpoint and store the cert in memory.
    /// This method should be called periodically to update the cert
    ///
    /// # Example
    /// ```
    /// use actix_web_jwt::CertInvoker;
    /// #[tokio::main]
    /// async fn main() {
    ///     let cert_url = String::from("https://www.googleapis.com/oauth2/v3/certs");
    ///     let cert_invoker = CertInvoker::from(cert_url);
    ///     cert_invoker.get_cert().await;
    /// }
    /// ```
    pub async fn get_cert(&self) {
        info!("Getting cert form {}", self.cert_url);
        let cert = get_cert(&self.cert_url).await;
        let mut jwt_cert = self.cert.lock().await;
        match cert {
            Ok(cert) => {
                *jwt_cert = Option::Some(cert);
            }
            Err(er) => {
                error!("Error while getting cert {:?}", er);
                *jwt_cert = Option::None;
            }
        }
    }
}

///
///
///
#[derive(Debug)]
pub enum JWKSError {
    ///
    /// Indicates error while invoking cert url
    ///
    InvokingCertUrl(String),
    ///
    /// Cert response is not valid
    ///
    ErrorDeserializingCert(String),
}

#[derive(Debug)]
pub struct JWTResponseError {
    pub status_code: StatusCode,
    pub message: String,
}

impl JWTResponseError {
    pub fn invalid_jwt() -> Self {
        JWTResponseError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Invalid JWT".to_string(),
        }
    }

    pub fn expired_jwt() -> Self {
        JWTResponseError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Expired JWT".to_string(),
        }
    }
    
    pub fn invalid_invalid_signature() -> Self {
        JWTResponseError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Invalid Invalid Signature".to_string(),
        }
    }

    pub fn invalid_invalid_issr() -> Self {
        JWTResponseError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Invalid Invalid Issure".to_string(),
        }
    }

    pub fn missing_jwt() -> Self {
        JWTResponseError {
            status_code: StatusCode::UNAUTHORIZED,
            message: "Missing JWT".to_string(),
        }
    }

    pub fn toke_validation_error(status_code:StatusCode, message: String ) -> Self {
        JWTResponseError {
            status_code,
            message,
        }
    }
}

impl error::ResponseError for JWTResponseError {
    fn status_code(&self) -> StatusCode {
        self.status_code
    }

    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code()).json(JWTResponse {
            message: self.message.clone(),
        })
    }
}

impl Display for JWTResponseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{:?}", self)
    }
}

#[derive(Serialize)]
pub struct JWTResponse {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct CertResponse {
    pub keys: Vec<KeyResponse>,
}

#[derive(Debug, Serialize, Deserialize)]
struct KeyResponse {
    pub kid: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub use_key: String,
    pub n: String,
    pub e: String,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,
    #[serde(rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
    pub alg: String,
}

impl Clone for CertResponse {
    fn clone(&self) -> Self {
        CertResponse {
            keys: self.keys.clone(),
        }
    }
}

impl Clone for KeyResponse {
    fn clone(&self) -> Self {
        KeyResponse {
            kid: self.kid.clone(),
            kty: self.kty.clone(),
            use_key: self.use_key.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
            alg: self.alg.clone(),
        }
    }
}

pub struct Cert {
    pub keys: Vec<Key>,
}


pub struct Key {
    pub kid: String,
    pub kty: String,
    pub use_key: String,
    pub n: String,
    pub e: String,
    pub x5c: Option<Vec<String>>,
    pub x5t: Option<String>,
    pub x5t_s256: Option<String>,
    pub alg: String,
    pub de_key: DecodingKey,
}

impl Clone for Cert {
    fn clone(&self) -> Self {
        Cert {
            keys: self.keys.clone(),
        }
    }
}

impl Clone for Key {
    fn clone(&self) -> Self {
        Key {
            kid: self.kid.clone(),
            kty: self.kty.clone(),
            use_key: self.use_key.clone(),
            n: self.n.clone(),
            e: self.e.clone(),
            x5c: self.x5c.clone(),
            x5t: self.x5t.clone(),
            x5t_s256: self.x5t_s256.clone(),
            alg: self.alg.clone(),
            de_key: self.de_key.clone(),
        }
    }
}


impl Key {
    
    fn from(key_response: KeyResponse, de_key: DecodingKey) -> Self {
        Key { kid: key_response.kid, kty: key_response.kty, use_key: key_response.use_key, 
            n: key_response.n, e: key_response.e, x5c: key_response.x5c, x5t: key_response.x5t, x5t_s256: key_response.x5t_s256, 
            alg: key_response.alg, de_key }
    }

}




#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Option<String>,
    pub exp: usize,
    pub nbf: Option<usize>,
    pub iat: usize,
    pub jti: Option<String>,
    pub azp: Option<String>,
    pub scope: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn get_cert_test() {
        let cert_url = String::from("https://www.googleapis.com/oauth2/v3/certs");
        let cert = get_cert(&cert_url).await;
        assert!(cert.is_ok());
    }

    #[tokio::test]
    async fn get_cert_wrong_url_test() {
        let cert_url = String::from("https://www.googleapis.com/oauth2/v3/certsx");
        let cert = get_cert(&cert_url).await;
        assert!(cert.is_err());
    }
}
