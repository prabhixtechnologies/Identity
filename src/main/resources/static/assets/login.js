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

    // --- Password fields --------------------------------------------------
    //
    // Three things, all of them about typing a password you cannot see.
    //
    // A reveal button, because a ten-character password typed blind on a phone keyboard is the
    // most common reason a sign-up is abandoned. A Caps Lock warning, because the other common
    // reason is a password that is right and rejected. And live feedback on the length rule, so
    // it is met before the form is submitted rather than learned by being turned away.
    //
    // All of it added by script. The markup ships without a reveal button on purpose: a control
    // that does nothing is worse than one that is not there.

    var passwordFields = document.querySelectorAll('input[type="password"]');

    Array.prototype.forEach.call(passwordFields, function (input) {
        var wrapper = input.parentNode;
        if (!wrapper || wrapper.className.indexOf("field-with-reveal") === -1) {
            return;
        }

        var reveal = document.createElement("button");
        reveal.type = "button";
        reveal.className = "reveal";
        reveal.setAttribute("aria-controls", input.id);
        // aria-pressed rather than changing the label, so a screen reader hears the state of one
        // control instead of a button that renames itself.
        reveal.setAttribute("aria-pressed", "false");
        reveal.setAttribute("aria-label", "Show password");
        reveal.textContent = "Show";
        wrapper.appendChild(reveal);

        reveal.addEventListener("click", function () {
            var shown = input.type === "text";
            input.type = shown ? "password" : "text";
            reveal.setAttribute("aria-pressed", shown ? "false" : "true");
            reveal.setAttribute("aria-label", shown ? "Show password" : "Hide password");
            reveal.textContent = shown ? "Show" : "Hide";
            // Focus back on the field with the caret at the end, so revealing mid-word does not
            // cost the place in it.
            input.focus();
            var end = input.value.length;
            try {
                input.setSelectionRange(end, end);
            } catch (ignore) {
                // Some browsers refuse setSelectionRange on a field mid-type change.
            }
        });

        var caps = document.getElementById("password-caps");
        if (caps) {
            var onKey = function (event) {
                // getModifierState is the only way to read Caps Lock, and it is unavailable on
                // events that did not come from a keyboard.
                if (typeof event.getModifierState !== "function") {
                    return;
                }
                caps.hidden = !event.getModifierState("CapsLock");
            };
            input.addEventListener("keydown", onKey);
            input.addEventListener("keyup", onKey);
            input.addEventListener("blur", function () {
                caps.hidden = true;
            });
        }

        var help = document.getElementById("password-help");
        var minLength = parseInt(input.getAttribute("minlength") || "0", 10);
        if (help && minLength > 0) {
            input.addEventListener("input", function () {
                var length = input.value.length;
                if (length === 0) {
                    help.textContent = "At least " + minLength + " characters.";
                    help.className = "hint";
                } else if (length < minLength) {
                    var left = minLength - length;
                    help.textContent = left === 1 ? "One more character." : left + " more characters.";
                    help.className = "hint hint--warn";
                } else {
                    help.textContent = "Long enough.";
                    help.className = "hint hint--ok";
                }
            });
        }
    });

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
    var passkeyError = document.getElementById("passkey-error");
    var passkeyLabel = passkeyButton.textContent;

    function sayPasskey(message) {
        if (!passkeyError) {
            // No place to put it, so fall back to the old behaviour rather than failing silently.
            window.location.href = "/login?error";
            return;
        }
        passkeyError.textContent = message;
        passkeyError.hidden = false;
    }

    /**
     * What actually went wrong, in words, on this page.
     *
     * Every failure used to become a reload to /login?error, which threw away the reason and the
     * typed address with it. Most of these are recoverable where you are standing - try again,
     * use the password, register a passkey on this device - and none of that is possible from a
     * blank page with a generic banner.
     */
    function passkeyMessage(err) {
        var name = err && err.name;
        if (name === "InvalidStateError") {
            return "This device already has a passkey for a different account. Sign in with your password instead.";
        }
        if (name === "SecurityError") {
            return "Passkeys will not work on this address. Sign in with your password.";
        }
        if (name === "AbortError") {
            return "That took too long. Try again, or sign in with your password.";
        }
        if (name === "NotSupportedError") {
            return "This browser cannot use passkeys. Sign in with your password.";
        }
        if (err && err.message === "no-passkey") {
            return "No passkey is registered for this account on this device. Sign in with your password, then add one from your account page.";
        }
        return "Could not sign in with a passkey. Try again, or use your password.";
    }

    passkeyButton.addEventListener("click", function () {
        if (passkeyError) {
            passkeyError.hidden = true;
        }
        // Said out loud as well as shown: the wait while the platform prompt appears is several
        // seconds on a cold start, and an unlabelled pause reads as a dead button.
        passkeyButton.disabled = true;
        passkeyButton.textContent = "Waiting for your passkey…";

        signInWithPasskey()
            .catch(function (err) {
                // Cancelling the platform prompt is a decision, not an error. Saying anything
                // about it would be telling somebody off for changing their mind.
                if (err && err.name === "NotAllowedError") {
                    return;
                }
                sayPasskey(passkeyMessage(err));
            })
            .then(function () {
                passkeyButton.disabled = false;
                passkeyButton.textContent = passkeyLabel;
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
            // 404 is the server saying this account has no passkey here, which is the single
            // most common failure and the one with the clearest next step.
            if (res.status === 404) {
                throw new Error("no-passkey");
            }
            if (!res.ok) {
                throw new Error("options failed");
            }
            return res.json();
        }).then(function (optionsJson) {
            if (optionsJson.allowCredentials && optionsJson.allowCredentials.length === 0 && email) {
                // An empty allow-list with a known address means the same thing: the browser
                // would show an empty chooser and the person would be left guessing.
                throw new Error("no-passkey");
            }
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
