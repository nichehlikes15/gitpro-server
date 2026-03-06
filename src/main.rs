use axum::{
    extract::Query,
    http::StatusCode,
    response::Redirect,
    routing::get,
    Router,
};
use reqwest::Client;
use serde::Deserialize;
use tokio::net::TcpListener;

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
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
        .route("/login", get(login))
        .route("/auth/github", get(auth_github));

    let listener = TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind address");

    println!("Server running on http://localhost:3000");

    axum::serve(listener, app)
        .await
        .expect("Server error");
}

async fn login() -> Redirect {
    let client_id =
        std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID missing");

    let redirect = format!(
        "https://github.com/login/oauth/authorize?scope=user:email&client_id={}",
        client_id
    );

    Redirect::to(&redirect)
}

async fn auth_github(
    Query(params): Query<CallbackQuery>,
) -> Result<Redirect, StatusCode> {
    let code = match params.code {
        Some(c) => c,
        None => {
            println!("OAuth code missing");
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    let client = Client::new();

    let client_id =
        std::env::var("GITHUB_CLIENT_ID").expect("GITHUB_CLIENT_ID missing");

    let client_secret = std::env::var("GITHUB_CLIENT_SECRET")
        .expect("GITHUB_CLIENT_SECRET missing");

    /* Exchange code → GitHub access token */

    println!("Sending Token To Github");

    let token_res = client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .json(&serde_json::json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code
        }))
        .send()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    if !token_res.status().is_success() {
        println!("GitHub token exchange failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    let token: GitHubTokenResponse = token_res
        .json()
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    println!("Received GitHub token: {}", token);
    println!("Access Token: {}", token.access_token);

    /* Verify token by requesting user */

    let user_res = client
        .get("https://api.github.com/user")
        .header(
            "Authorization",
            format!("token {}", token.access_token),
        )
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

    let login = user["login"]
        .as_str()
        .unwrap_or("unknown");

    println!("Authenticated GitHub user: {}", login);

    /* Redirect back to client with GitHub token */

    Ok(Redirect::to(&format!(
        "http://127.0.0.1:49152/callback?token={}",
        token.access_token
    )))
}