// Regression fixture for sast/rust-auth (data only, never compiled).
use axum::extract::{Path, State};
use axum::routing::{delete, get, post, put};
use axum::{middleware, Json, Router};

const DEFAULT_PASSWORD: &str = "Welcome123";

async fn reset_password(State(db): State<Db>, Json(req): Json<ResetReq>) -> StatusCode {
    let pw = req.new_password.unwrap_or("Welcome123".to_string());
    db.set_password(&req.email, &hash(&pw)).await;
    StatusCode::OK
}

async fn register(State(db): State<Db>, Json(req): Json<RegisterReq>) -> StatusCode {
    db.create_user(&req.email, &hash(DEFAULT_PASSWORD)).await;
    StatusCode::CREATED
}

async fn change_password(user: AuthUser, State(db): State<Db>, Json(req): Json<ChangeReq>) -> StatusCode {
    store_new_password(&db, user.id, &req.new_password).await;
    StatusCode::OK
}

async fn store_new_password(db: &Db, id: i64, pw: &str) {
    db.update_password(id, &hash(pw)).await;
}

async fn delete_user(State(db): State<Db>, Path(id): Path<i64>) -> StatusCode {
    db.delete_user(id).await;
    StatusCode::NO_CONTENT
}

async fn delete_order(user: AuthUser, State(db): State<Db>, Path(id): Path<i64>) -> StatusCode {
    require_permission(&user, "orders:read")?;
    db.delete_order(id).await;
    StatusCode::NO_CONTENT
}

async fn update_profile(State(db): State<Db>, Json(p): Json<Profile>) -> StatusCode {
    db.save_profile(p).await;
    StatusCode::OK
}

async fn admin_flush_cache(State(cache): State<Cache>) -> StatusCode {
    cache.clear_all().await;
    StatusCode::OK
}

async fn require_auth(req: Request, next: Next) -> Response {
    let token = req.headers().get(AUTHORIZATION);
    next.run(req).await
}

fn admin_routes() -> Router<AppState> {
    Router::new().route("/users/:id", delete(delete_user))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/password/reset", post(reset_password))
        .route("/register", post(register))
        .route("/password/change", post(change_password))
        .route("/orders/:id", delete(delete_order))
        .route("/profile", put(update_profile))
        // route_layer only wraps the routes registered above it.
        .route_layer(middleware::from_fn(require_auth))
        .route("/admin/cache", post(admin_flush_cache))
        .nest("/admin", admin_routes());
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
