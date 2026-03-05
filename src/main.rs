use axum::{
    Router,
    extract::Query,
    http::StatusCode,
    response::Redirect,
    routing::get,
};
use serde::Deserialize;
use reqwest::Client;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct CallbackQueryParameters {
    code: String,
}

#[derive(Deserialize, Debug)]
struct GitHubTokenResponse {
    access_token: String,
    token_type: String,
    scope: String,
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

async fn auth_github(
    Query(params): Query<CallbackQueryParameters>
) -> Result<Redirect, StatusCode> {

    let client = Client::new();

    let client_id = std::env::var("GITHUB_CLIENT_ID")
        .expect("GITHUB_CLIENT_ID missing");

    let client_secret = std::env::var("GITHUB_CLIENT_SECRET")
        .expect("GITHUB_CLIENT_SECRET missing");

    // 1️⃣ Exchange code for GitHub access token
    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": params.code
        }))
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !token_res.status().is_success() {
        println!("GitHub token exchange failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token_body: GitHubTokenResponse = token_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    println!("GitHub access token received");

    // 2️⃣ Verify token by requesting GitHub user
    let user_res = client
        .get("https://api.github.com/user")
        .header("Authorization", format!("token {}", token_body.access_token))
        .header("User-Agent", "gitpro-webserver")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !user_res.status().is_success() {
        println!("GitHub token invalid");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user: serde_json::Value = user_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let github_login = user["login"]
        .as_str()
        .unwrap_or("unknown");

    println!("Authenticated GitHub user: {}", github_login);

    // 3️⃣ Send GitHub token to client
    Ok(Redirect::to(&format!(
        "http://127.0.0.1:49152/callback?token={}",
        token_body.access_token
    )))
}