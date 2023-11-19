# JWT validation middleware for actix-web

This middleware validates the JWT using the JWKS. 

## Usage
```
cargo add actix-web-jwt
```

## Examples

```rust
use std::sync::Arc;

use actix_web::HttpServer;
use actix_web_jwt::{Jwt, CertInvoker};
use tokio_cron_scheduler::{JobScheduler, Job};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    
    let invoker = CertInvoker::from(String::from("https://www.googleapis.com/oauth2/v3/certs"));

    let arc_jwt = Arc::new(invoker);
    let cloned_arc_jwt = Arc::clone(&arc_jwt);

    let sched = JobScheduler::new().await.unwrap();
    
    let job = Job::new_async("1/10 * * * * *", move |_uuid, mut _l| {
        let cloned_arc_jwt = Arc::clone(&cloned_arc_jwt);
        Box::pin(async move {
            cloned_arc_jwt.get_cert().await;
        })
    })
    .unwrap();
    sched.add(job).await.unwrap();
    let scheduler = sched.start();
    
    let server = HttpServer::new(move || {
        actix_web::App::new()
            .wrap(Jwt::from(Arc::clone(&arc_jwt), Some(Arc::new(Validate{}))))
    })
    .bind("127.0.0.1:8080")
    .unwrap()
    .run();

    let _ = futures::future::join(scheduler, server).await;
    Ok(())
}

struct Validate;

impl JWTValidator for Validate {
    
    fn validate(&self,toke_data:TokenData<Claims>) -> Result<(), JWTResponseError> {
        println!("validate token data: {:?}", toke_data);
        if let Some(aud) = toke_data.claims.aud {
            if aud != "1234567890" {
                return Err(JWTResponseError::toke_validation_error(StatusCode::UNAUTHORIZED, "aud error".to_string()));
            }
        }
        Ok(())
    }
}

```