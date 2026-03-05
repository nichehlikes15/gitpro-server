use axum::{
    Json, Router, extract::Query, http::StatusCode, routing::{get, post}
};
use serde::{Deserialize, Serialize};
use jsonwebtoken::{encode, Header, EncodingKey};
use chrono::{Utc, Duration};
use reqwest::Client;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct OAuthRequest {
    code: String,
}

#[derive(Serialize)]
struct ApiTokenResponse {
    token: String,
}

#[derive(Serialize, Deserialize)]
struct Claims {
    sub: u64,
    exp: usize,
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
}

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let app = Router::new()
        .route("/auth/github", get(auth_github));

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind address");

    println!("Server running on http://0.0.0.0:3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

#[derive(Deserialize)]
struct CallbackQueryParameters {
    code: String
}

async fn auth_github(
    Query(params): Query<CallbackQueryParameters>
) -> Result<Json<ApiTokenResponse>, StatusCode> {
    let client = Client::new();
    let client_id = std::env::var("GITHUB_CLIENT_ID")
        .expect("GITHUB_CLIENT_ID missing");
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET")
        .expect("GITHUB_CLIENT_SECRET missing");

    /* 1️⃣ Exchange code → GitHub access token */
    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": params.code,
        }))
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !token_res.status().is_success() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_body: GitHubTokenResponse = token_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    /* 2️⃣ Use GitHub token to fetch user */
    let user_res = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {}", token_body.access_token))
        .header("User-Agent", "gitpro-webserver")
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !user_res.status().is_success() {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user: serde_json::Value = user_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let github_id = user["id"]
        .as_u64()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    /* 3️⃣ Issue YOUR JWT */
    let expiration = (Utc::now() + Duration::hours(24)).timestamp() as usize;

    let claims = Claims {
        sub: github_id,
        exp: expiration,
    };

    let jwt_secret = std::env::var("JWT_SECRET")
        .expect("JWT_SECRET missing");

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    ).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(ApiTokenResponse { token }))
}