// Regression fixture for sast/rust-auth (data only, never compiled).
use actix_web::{delete, get, post, web, App, HttpResponse, HttpServer};

#[post("/account/password")]
async fn change_password(user: AuthUser, form: web::Json<ChangePw>) -> HttpResponse {
    db::update_password(user.id, &form.new_password);
    HttpResponse::Ok().finish()
}

#[delete("/users/{id}")]
async fn delete_user(path: web::Path<i64>) -> HttpResponse {
    db::delete_user(path.into_inner());
    HttpResponse::NoContent().finish()
}

#[get("/health")]
async fn health() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn rotate_keys(data: web::Data<AppState>) -> HttpResponse {
    data.keys.rotate();
    HttpResponse::Ok().finish()
}

mod db {
    pub fn update_password(id: i64, pw: &str) {}
    pub fn delete_user(id: i64) {}
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .service(web::scope("/admin").service(delete_user))
            .service(web::resource("/keys/rotate").route(web::post().to(rotate_keys)))
            .service(change_password)
            .service(health)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
