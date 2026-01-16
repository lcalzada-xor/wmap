// Running immediately as script is deferred/at end of body
const form = document.getElementById('login-form');
const errorMsg = document.getElementById('error-msg');

if (form) {
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const btn = form.querySelector('button');

        btn.innerText = "AUTHENTICATING...";
        btn.disabled = true;
        errorMsg.style.opacity = '0';

        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            if (response.ok) {
                window.location.href = '/';
            } else {
                throw new Error('Invalid credentials');
            }
        } catch (err) {
            errorMsg.innerText = "ACCESS DENIED: INVALID CREDENTIALS";
            errorMsg.style.opacity = '1';
            btn.innerText = "Initialize Link";
            btn.disabled = false;
        }
    });
}

// Logout Helper (exposed globally if this script is included in main app)
window.logout = async () => {
    try {
        await fetch('/api/logout', { method: 'POST' });
        window.location.href = '/login.html';
    } catch (err) {
        console.error("Logout failed", err);
    }
};
