import { API } from '../../core/api.js';
import { Notifications } from '../notifications.js';

export class SessionModal {
    static init(onSuccess) {
        const modal = document.getElementById('session-modal');
        const select = document.getElementById('session-select');
        const btnLoad = document.getElementById('btn-session-load');
        const btnCreate = document.getElementById('btn-session-create');
        const inputNew = document.getElementById('session-new-name');

        if (!modal) return;

        // Show/Hide via CSS Class
        const show = () => {
            console.log("Showing Session Modal");
            modal.classList.add('active');
            modal.style.display = 'flex';
            modal.style.opacity = '1';
            // Force Z-index to ensure it sits on top of everything
            modal.style.zIndex = '10000';
            modal.style.pointerEvents = 'auto'; // Ensure clickable
        };
        const hide = () => {
            console.log("Hiding Session Modal");
            modal.classList.remove('active');
            modal.style.display = 'none';
            modal.style.opacity = '0';
        };

        // Load Sessions List
        API.listSessions().then(data => {
            select.innerHTML = '<option value="">-- Select Session --</option>';
            (data.sessions || []).forEach(s => {
                const opt = document.createElement('option');
                opt.value = s;
                opt.innerText = s;
                select.appendChild(opt);
            });
            show();
        }).catch(err => {
            console.error("Failed to list sessions", err);
            // Even if listing fails, we MUST show the modal so user can try to create one or see the error
            select.innerHTML = '<option value="">Error loading sessions</option>';
            Notifications.show("Could not list sessions: " + err.message, "danger");
            show();
        });

        // Handlers
        btnLoad.onclick = () => {
            const name = select.value;
            if (!name) return Notifications.show("Please select a session", "danger");

            API.loadSession(name).then(() => {
                hide();
                Notifications.show("Session Loaded", "success");
                if (onSuccess) onSuccess();
            }).catch(err => Notifications.show("Load Failed: " + err.message, "danger"));
        };

        btnCreate.onclick = () => {
            const name = inputNew.value.trim();
            if (!name) return Notifications.show("Enter a session name", "danger");

            API.createSession(name).then(() => {
                hide();
                Notifications.show("Session Created", "success");
                if (onSuccess) onSuccess();
            }).catch(err => Notifications.show("Create Failed: " + err.message, "danger"));
        };
    }
}
