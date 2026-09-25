// Progressive enhancement for the hosted login page: theme toggle, Google GIS, and passkeys.
//
// Passwordless form posts work with no script at all. This file only adds the methods that need a
// browser API — and its absence costs those buttons rather than the page.
(function () {
    "use strict";

    var script = document.currentScript;
    var clientId = script && script.dataset.clientId;
    var email = script && script.dataset.email;
    var csrfToken = script && script.dataset.csrfToken;
    var csrfHeader = script && script.dataset.csrfHeader;

    // --- Theme (data-theme + localStorage) ---------------------------------

    var root = document.documentElement;
    var themeToggle = document.getElementById("theme-toggle");

    function preferredTheme() {
        try {
            var stored = localStorage.getItem("prabhix-theme");
            if (stored === "light" || stored === "dark") {
                return stored;
            }
        } catch (ignore) {
            // Private mode can refuse localStorage; fall through to system preference.
        }
        return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
    }

    function applyTheme(theme) {
        root.setAttribute("data-theme", theme);
        if (themeToggle) {
            themeToggle.setAttribute("aria-label",
                theme === "dark" ? "Switch to light theme" : "Switch to dark theme");
        }
    }

    applyTheme(preferredTheme());

    if (themeToggle) {
        themeToggle.addEventListener("click", function () {
            var next = root.getAttribute("data-theme") === "dark" ? "light" : "dark";
            applyTheme(next);
            try {
                localStorage.setItem("prabhix-theme", next);
            } catch (ignore) {
                // Preference is lost on refresh; the toggle still works for this visit.
            }
        });
    }

    // --- Google GIS -------------------------------------------------------

    var mount = document.getElementById("google-button");
    var form = document.getElementById("google-form");
    var field = document.getElementById("google-credential");

    function renderGoogle() {
        if (!clientId || !mount || !form || !field) {
            return true;
        }
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
            theme: root.getAttribute("data-theme") === "dark" ? "filled_black" : "outline",
            size: "large",
            text: "continue_with",
            shape: "pill",
            width: mount.offsetWidth || 320
        });
        return true;
    }

    if (clientId && mount && form && field) {
        if (!renderGoogle()) {
            var attempts = 0;
            var timer = setInterval(function () {
                if (renderGoogle() || ++attempts > 40) {
                    clearInterval(timer);
                }
            }, 100);
        }
    }

    // --- Passkeys ---------------------------------------------------------

    var passkeyButton = document.getElementById("passkey-button");
    if (!passkeyButton || !window.PublicKeyCredential) {
        return;
    }

    passkeyButton.hidden = false;
    passkeyButton.addEventListener("click", function () {
        signInWithPasskey().catch(function (err) {
            if (err && err.name === "NotAllowedError") {
                return;
            }
            window.location.href = "/login?error";
        });
    });

    function headers() {
        var h = { "Content-Type": "application/json", "Accept": "application/json" };
        if (csrfToken && csrfHeader) {
            h[csrfHeader] = csrfToken;
        }
        return h;
    }

    function b64urlToBuffer(value) {
        var str = value.replace(/-/g, "+").replace(/_/g, "/");
        while (str.length % 4) {
            str += "=";
        }
        var binary = atob(str);
        var bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    function bufferToB64url(buffer) {
        var bytes = new Uint8Array(buffer);
        var binary = "";
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
    }

    function parseRequestOptions(json) {
        if (window.PublicKeyCredential && typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
            return PublicKeyCredential.parseRequestOptionsFromJSON(json);
        }
        var options = Object.assign({}, json);
        options.challenge = b64urlToBuffer(json.challenge);
        if (json.allowCredentials) {
            options.allowCredentials = json.allowCredentials.map(function (cred) {
                return Object.assign({}, cred, { id: b64urlToBuffer(cred.id) });
            });
        }
        return options;
    }

    function credentialToJson(credential) {
        if (typeof credential.toJSON === "function") {
            return credential.toJSON();
        }
        var response = credential.response;
        return {
            id: credential.id,
            rawId: bufferToB64url(credential.rawId),
            type: credential.type,
            authenticatorAttachment: credential.authenticatorAttachment,
            response: {
                clientDataJSON: bufferToB64url(response.clientDataJSON),
                authenticatorData: bufferToB64url(response.authenticatorData),
                signature: bufferToB64url(response.signature),
                userHandle: response.userHandle ? bufferToB64url(response.userHandle) : null
            },
            clientExtensionResults: credential.getClientExtensionResults
                ? credential.getClientExtensionResults()
                : {}
        };
    }

    function signInWithPasskey() {
        return fetch("/login/passkey/options", {
            method: "POST",
            credentials: "same-origin",
            headers: headers(),
            body: JSON.stringify({ email: email || null })
        }).then(function (res) {
            if (!res.ok) {
                throw new Error("options failed");
            }
            return res.json();
        }).then(function (optionsJson) {
            return navigator.credentials.get({ publicKey: parseRequestOptions(optionsJson) });
        }).then(function (credential) {
            if (!credential) {
                throw new DOMException("cancelled", "NotAllowedError");
            }
            return fetch("/login/passkey/verify", {
                method: "POST",
                credentials: "same-origin",
                redirect: "manual",
                headers: headers(),
                body: JSON.stringify({ credential: credentialToJson(credential) })
            });
        }).then(function (res) {
            // HostedSignIn answers with a redirect to /authorize or the console.
            if (res.status === 0 || (res.status >= 300 && res.status < 400)) {
                window.location.href = res.url || "/";
                return;
            }
            if (res.ok) {
                window.location.href = res.url || "/";
                return;
            }
            window.location.href = "/login?error";
        });
    }
})();
