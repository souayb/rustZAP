// Regression fixture for sast/rust-auth (data only, never compiled).
use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, post, put};
use axum::{middleware, Json, Router};

async fn reset_password(State(db): State<Db>, Json(req): Json<ResetReq>) -> Result<StatusCode, Error> {
    let pw = req.new_password.ok_or(Error::BadRequest)?;
    db.set_password(&req.email, &hash(&pw)).await;
    revoke_all_sessions(&db, &req.email).await;
    Ok(StatusCode::OK)
}

async fn register(State(db): State<Db>, Json(req): Json<RegisterReq>) -> StatusCode {
    // Required configuration: refuses to start without it.
    let initial = std::env::var("INITIAL_PASSWORD").expect("INITIAL_PASSWORD must be set");
    db.create_user(&req.email, &hash(&initial)).await;
    StatusCode::CREATED
}

async fn change_password(user: AuthUser, State(db): State<Db>, Json(req): Json<ChangeReq>) -> StatusCode {
    store_new_password(&db, user.id, &req.new_password).await;
    StatusCode::OK
}

async fn store_new_password(db: &Db, id: i64, pw: &str) {
    db.update_password(id, &hash(pw)).await;
    db.bump_token_version(id).await;
}

async fn delete_user(State(db): State<Db>, Path(id): Path<i64>) -> StatusCode {
    db.delete_user(id).await;
    StatusCode::NO_CONTENT
}

async fn delete_order(user: AuthUser, State(db): State<Db>, Path(id): Path<i64>) -> StatusCode {
    require_permission(&user, "orders:write")?;
    db.delete_order(id).await;
    StatusCode::NO_CONTENT
}

// Helper-wrapped check: no extractor, no layer, auth happens two calls down.
async fn delete_comment(State(db): State<Db>, Path(id): Path<i64>, headers: HeaderMap) -> StatusCode {
    let actor = load_actor(&headers)?;
    db.delete_comment(id, actor).await;
    StatusCode::NO_CONTENT
}

fn load_actor(headers: &HeaderMap) -> Result<Actor, Error> {
    let claims = verify_jwt(headers.get("x-session"))?;
    Ok(Actor::from(claims))
}

// Middleware whose name says nothing; it is resolved through the call graph.
async fn admin_only(req: Request, next: Next) -> Result<Response, StatusCode> {
    let claims = decode_jwt(req.headers())?;
    next.run(req).await
}

fn admin_routes() -> Router<AppState> {
    Router::new()
        .route("/users/:id", delete(delete_user))
        .route_layer(middleware::from_fn(admin_only))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/password/reset", post(reset_password))
        .route("/register", post(register))
        .route("/password/change", post(change_password))
        .route("/orders/:id", delete(delete_order))
        .route("/comments/:id", delete(delete_comment))
        .nest("/admin", admin_routes());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

#[cfg(test)]
mod tests {
    const DEFAULT_PASSWORD: &str = "Welcome123";

    fn seed(new_password: Option<String>) -> String {
        new_password.unwrap_or("Welcome123".to_string())
    }
}
