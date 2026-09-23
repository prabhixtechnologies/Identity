// Passkey enrolment on /account. Theme toggle lives in login.js; this file only adds create().
(function () {
    "use strict";

    var script = document.currentScript;
    var csrfToken = script && script.dataset.csrfToken;
    var csrfHeader = script && script.dataset.csrfHeader;
    var returnTo = script && script.dataset.returnTo;
    var enrol = document.getElementById("passkey-enrol");
    if (!enrol || !window.PublicKeyCredential) {
        return;
    }

    enrol.hidden = false;
    enrol.addEventListener("click", function () {
        enrol.disabled = true;
        registerPasskey().catch(function (err) {
            enrol.disabled = false;
            if (err && err.name === "NotAllowedError") {
                return;
            }
            window.location.href = "/account?view=security&error=" + encodeURIComponent(
                "That passkey could not be added. Try again.")
                + (returnTo ? "&return_to=" + encodeURIComponent(returnTo) : "");
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

    function parseCreationOptions(json) {
        if (window.PublicKeyCredential && typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
            return PublicKeyCredential.parseCreationOptionsFromJSON(json);
        }
        var options = Object.assign({}, json);
        options.challenge = b64urlToBuffer(json.challenge);
        if (json.user && json.user.id) {
            options.user = Object.assign({}, json.user, { id: b64urlToBuffer(json.user.id) });
        }
        if (json.excludeCredentials) {
            options.excludeCredentials = json.excludeCredentials.map(function (cred) {
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
                attestationObject: bufferToB64url(response.attestationObject),
                transports: response.getTransports ? response.getTransports() : []
            },
            clientExtensionResults: credential.getClientExtensionResults
                ? credential.getClientExtensionResults()
                : {}
        };
    }

    function registerPasskey() {
        var labelField = document.getElementById("passkey-label");
        var label = labelField && labelField.value ? labelField.value : "Passkey";
        return fetch("/account/passkey/options", {
            method: "POST",
            credentials: "same-origin",
            headers: headers(),
            body: "{}"
        }).then(function (res) {
            if (!res.ok) {
                if (res.status === 401 || res.status === 403 || res.redirected) {
                    window.location.href = "/login";
                    return;
                }
                throw new Error("options failed");
            }
            return res.json();
        }).then(function (optionsJson) {
            return navigator.credentials.create({ publicKey: parseCreationOptions(optionsJson) });
        }).then(function (credential) {
            if (!credential) {
                throw new DOMException("cancelled", "NotAllowedError");
            }
            return fetch("/account/passkey/finish", {
                method: "POST",
                credentials: "same-origin",
                headers: headers(),
                body: JSON.stringify({ credential: credentialToJson(credential), label: label })
            });
        }).then(function (res) {
            if (!res.ok) {
                throw new Error("finish failed");
            }
            window.location.href = "/account?view=security&saved=passkey-added"
                + (returnTo ? "&return_to=" + encodeURIComponent(returnTo) : "");
        });
    }
})();
