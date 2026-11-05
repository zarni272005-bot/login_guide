let csrfToken = "";

const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");
const accountView = document.getElementById("account-view");

function showForm(formName) {
    const showRegister = formName === "register";
    loginForm.hidden = showRegister;
    registerForm.hidden = !showRegister;
    accountView.hidden = true;
}

function showAccount(account) {
    loginForm.hidden = true;
    registerForm.hidden = true;
    accountView.hidden = false;
    document.getElementById("account-details").textContent =
        `${account.name} · ${account.contact}`;
    history.replaceState(null, "", `${location.pathname}${location.search}`);
}

function updateIdentifier(toggle, button) {
    const identifier = toggle.parentElement.querySelector("[data-identifier]");
    const usePhone = button.dataset.identifierMethod === "phone";
    identifier.type = usePhone ? "tel" : "email";
    identifier.placeholder = usePhone ? "Phone number" : "Email address";
    identifier.setAttribute("aria-label", usePhone ? "Phone number" : "Email address");
    identifier.autocomplete = usePhone ? "tel" : "email";

    toggle.querySelectorAll("[data-identifier-method]").forEach((methodButton) => {
        const isActive = methodButton === button;
        methodButton.classList.toggle("active", isActive);
        methodButton.setAttribute("aria-pressed", String(isActive));
    });
}

async function apiRequest(path, options = {}) {
    const headers = new Headers(options.headers);
    headers.set("Accept", "application/json");
    if (options.body) {
        headers.set("Content-Type", "application/json");
        headers.set("X-CSRF-Token", csrfToken);
    }

    const response = await fetch(path, {
        ...options,
        headers,
        credentials: "same-origin",
    });
    const result = await response.json();
    if (!response.ok) {
        throw new Error(result.error || "Something went wrong. Please try again.");
    }
    return result;
}

document.querySelectorAll(".login-method-toggle").forEach((toggle) => {
    toggle.querySelectorAll("[data-identifier-method]").forEach((button) => {
        button.addEventListener("click", () => updateIdentifier(toggle, button));
    });
});

document.querySelectorAll("[data-show-form]").forEach((link) => {
    link.addEventListener("click", (event) => {
        event.preventDefault();
        const formName = link.dataset.showForm;
        showForm(formName);
        history.pushState(null, "", `#${formName}`);
    });
});

window.addEventListener("hashchange", () => {
    showForm(location.hash === "#register" ? "register" : "login");
});

document.querySelectorAll("[data-provider]").forEach((button) => {
    button.addEventListener("click", () => {
        const message = button.closest(".form-box").querySelector(".auth-message");
        message.textContent = `${button.dataset.provider} sign-in needs OAuth configuration before it can be used.`;
    });
});

document.querySelectorAll("[data-auth-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const formName = form.dataset.authForm;
        const message = document.getElementById(`${formName}-message`);
        const submitButton = form.querySelector('button[type="submit"]');
        const activeMethod = form.querySelector(".method-button.active");
        const formData = new FormData(form);
        const data = {
            contactType: activeMethod.dataset.identifierMethod,
            identifier: formData.get("identifier"),
            password: formData.get("password"),
        };
        if (formName === "register") {
            data.name = formData.get("name");
        }

        submitButton.disabled = true;
        message.textContent = formName === "register" ? "Creating your account..." : "Signing in...";
        try {
            const result = await apiRequest(`/api/${formName}`, {
                method: "POST",
                body: JSON.stringify(data),
            });
            csrfToken = result.csrfToken;
            showAccount(result.account);
        } catch (error) {
            message.textContent = error.message;
        } finally {
            submitButton.disabled = false;
        }
    });
});

document.getElementById("logout-button").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
        await apiRequest("/api/logout", { method: "POST", body: "{}" });
        const csrf = await apiRequest("/api/csrf");
        csrfToken = csrf.csrfToken;
        showForm("login");
        history.replaceState(null, "", `${location.pathname}${location.search}#login`);
        document.getElementById("login-message").textContent = "You have been signed out.";
    } catch (error) {
        document.getElementById("account-details").textContent = error.message;
    } finally {
        button.disabled = false;
    }
});

async function initialize() {
    showForm(location.hash === "#register" ? "register" : "login");
    try {
        const csrf = await apiRequest("/api/csrf");
        csrfToken = csrf.csrfToken;
        const current = await apiRequest("/api/me");
        if (current.authenticated) {
            showAccount(current.account);
        }
    } catch (_error) {
        document.getElementById("login-message").textContent =
            "The account service is unavailable. Start the Python server and refresh.";
    }
}

initialize();
