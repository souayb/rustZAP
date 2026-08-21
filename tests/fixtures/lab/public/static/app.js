// Deliberately-vulnerable client script — SAST bait for the native analyzers.
// Fake credentials only; this file is never executed in CI.

// sast/js-secrets — hardcoded credentials in client code.
const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwx";
const STRIPE_KEY = "set-in-env-never-hardcode";
const config = { api_key: "hardcoded-api-key-value-123456" };

// sast/js-urls — hardcoded backend endpoint.
fetch("https://api.example.invalid/v1/patients");

// sast/dom-sinks — untrusted data flowing into HTML/eval sinks (CWE-79).
document.getElementById("out").innerHTML = location.hash;
document.write(window.name);
eval(location.search.slice(1));
new Function("return " + document.referrer)();
element.insertAdjacentHTML("beforeend", location.hash);

// sast/js-cookies — writing/reading document.cookie (CWE-565).
document.cookie = "session=" + location.hash;
const raw = document.cookie;

// sast/js-storage — auth material in web storage (CWE-922).
localStorage.setItem("token", config.api_key);
sessionStorage.theme = window.name;

// sast/js-postmessage — unrestricted target origin (CWE-346).
window.postMessage(location.hash, "*");

//# sourceMappingURL=app.js.map
