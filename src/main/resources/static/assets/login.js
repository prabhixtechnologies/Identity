// Renders Google's sign-in button and hands the credential it returns to our own form.
//
// Loaded only when a client id is configured, and everything else on the page works without it.
//
// Google can POST the credential straight to a login_uri, which is simpler and worse: that request
// comes from Google's frame, so it is cross-site, carries no CSRF token, and the endpoint would have
// to be exempted from the check. Passing it through a same-origin form keeps the token.
(function () {
    "use strict";

    var script = document.currentScript;
    var clientId = script && script.dataset.clientId;
    var mount = document.getElementById("google-button");
    var form = document.getElementById("google-form");
    var field = document.getElementById("google-credential");

    if (!clientId || !mount || !form || !field) {
        return;
    }

    function render() {
        if (!window.google || !window.google.accounts || !window.google.accounts.id) {
            return false;
        }
        window.google.accounts.id.initialize({
            client_id: clientId,
            callback: function (response) {
                if (!response || !response.credential) {
                    return;
                }
                field.value = response.credential;
                form.submit();
            }
        });
        window.google.accounts.id.renderButton(mount, {
            theme: "outline",
            size: "large",
            text: "continue_with",
            shape: "pill",
            width: mount.offsetWidth || 320
        });
        return true;
    }

    // Google's script is async, so it may not have defined window.google yet. Polled briefly rather
    // than waited on with an onload hook, because that hook belongs to a script tag this file does
    // not own; if it never arrives the page is simply the one button short.
    if (!render()) {
        var attempts = 0;
        var timer = setInterval(function () {
            if (render() || ++attempts > 40) {
                clearInterval(timer);
            }
        }, 100);
    }
})();
