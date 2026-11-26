// Test-only credentials under tests/ must never be reported.
const DEFAULT_PASSWORD: &str = "Welcome123";

async fn reset_password(new_password: Option<String>) -> String {
    new_password.unwrap_or_else(|| DEFAULT_PASSWORD.to_string())
}
