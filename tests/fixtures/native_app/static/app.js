/* Fixture only — keys are obviously fake and used to exercise regex detectors. */
const api_key = "test_key_not_a_real_secret_zz";
const demoAws = "AKIAEXAMPLEKEYFAKE00";

document.getElementById("out").innerHTML = location.hash;
const vnode = { dangerouslySetInnerHTML: { __html: window.name } };

fetch("https://example.invalid/api/v1");

document.cookie = "session=" + location.hash;
const cookieDump = document.cookie;
localStorage.setItem("token", cookieDump);
sessionStorage.theme = window.name;
window.postMessage(location.hash, "*");

//# sourceMappingURL=app.js.map
