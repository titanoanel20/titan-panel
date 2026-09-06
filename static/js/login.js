/* ============================================================
   TiTaN Login — connected to the real panel API
   (design preserved: username-first, password only when needed)
============================================================ */

(function () {

    const form =
        document.getElementById("loginForm");

    const username =
        document.getElementById("username");

    const password =
        document.getElementById("password");

    const passwordRow =
        document.getElementById("passwordRow");

    const message =
        document.getElementById("message");

    const loginButton =
        document.getElementById("loginButton");


    /* ============================================================
       PASSWORD FIELD
       In the default (first-run) state there is no password, so the
       password box stays hidden. If the admin has set a password
       (default_auth === false), we reveal it so login keeps working.
    ============================================================ */

    function syncPasswordVisibility() {
        fetch("/api/me", { credentials: "same-origin" })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                if (passwordRow) {
                    passwordRow.classList.toggle(
                        "visible",
                        data.default_auth === false
                    );
                }
            })
            .catch(function () { /* keep hidden by default */ });
    }

    syncPasswordVisibility();


    /* ============================================================
       LOGIN
    ============================================================ */

    form.addEventListener("submit", async function (event) {

        event.preventDefault();

        const value =
            username.value.trim();

        const pass =
            (password && password.value) || "";


        /*
         * خالی بودن نام کاربری
         */

        if (!value) {

            showMessage(
                "لطفاً نام کاربری را وارد کنید.",
                "error"
            );

            username.focus();

            return;

        }


        /*
         * وضعیت Loading
         */

        loginButton.disabled = true;

        loginButton.classList.add("loading");

        loginButton.querySelector("span").textContent =
            "در حال ورود...";


        showMessage(
            "در حال بررسی اطلاعات...",
            "normal"
        );


        try {

            const response = await fetch("/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: value,
                    password: pass,
                    remember: true
                })
            });

            let data = {};
            try { data = await response.json(); } catch (e) { /* noop */ }

            if (response.ok && data.ok) {

                showMessage(
                    "ورود موفق — در حال انتقال...",
                    "success"
                );

                setTimeout(function () {
                    window.location.href = "/dashboard";
                }, 350);

                return;
            }

            const detail = data.detail || "";

            if (response.status === 429 && detail.indexOf("locked") === 0) {
                const secs = parseInt(detail.split(":")[1] || "60", 10);
                showMessage(
                    "تلاش‌های زیاد — " + secs + " ثانیه بعد دوباره امتحان کنید.",
                    "error"
                );
            } else if (response.status === 401) {
                showMessage(
                    "نام کاربری یا رمز عبور اشتباه است.",
                    "error"
                );
            } else {
                showMessage(
                    "خطایی هنگام ورود رخ داد.",
                    "error"
                );
            }

        } catch (error) {

            console.error(error);

            showMessage(
                "عدم اتصال به سرور — اتصال اینترنت را بررسی کنید.",
                "error"
            );

        }


        loginButton.disabled = false;

        loginButton.classList.remove("loading");

        loginButton.querySelector("span").textContent =
            "ورود";

    });


    /* ============================================================
       MESSAGE
    ============================================================ */

    function showMessage(text, type) {

        message.textContent =
            text;

        message.className =
            "message";

        if (type) {
            message.classList.add(type);
        }

    }


    /* ============================================================
       INPUT
    ============================================================ */

    username.addEventListener(
        "input",
        function () {
            message.textContent = "";
            message.className = "message";
        }
    );

    if (password) {
        password.addEventListener(
            "input",
            function () {
                message.textContent = "";
                message.className = "message";
            }
        );
    }


    /* ============================================================
       ENTER KEY
    ============================================================ */

    username.addEventListener(
        "keydown",
        function (event) {
            if (event.key === "Enter") {
                event.preventDefault();
                form.requestSubmit();
            }
        }
    );

    if (password) {
        password.addEventListener(
            "keydown",
            function (event) {
                if (event.key === "Enter") {
                    event.preventDefault();
                    form.requestSubmit();
                }
            }
        );
    }

})();
