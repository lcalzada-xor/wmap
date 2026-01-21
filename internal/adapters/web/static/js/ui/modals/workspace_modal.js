import { API } from '../../core/api.js';
import { Notifications } from '../notifications.js';

export class WorkspaceModal {
    static init(onSuccess) {
        const modal = document.getElementById('workspace-modal');
        const select = document.getElementById('workspace-select');
        const btnLoad = document.getElementById('btn-workspace-load');
        const btnDelete = document.getElementById('btn-workspace-delete');
        const btnCreate = document.getElementById('btn-workspace-create');
        const inputNew = document.getElementById('workspace-new-name');

        if (!modal) return;

        // Show/Hide via CSS Class
        const show = () => {

            modal.classList.add('active');
            modal.style.display = 'flex';
            modal.style.opacity = '1';
            // Force Z-index to ensure it sits on top of everything
            modal.style.zIndex = '10000';
            modal.style.pointerEvents = 'auto'; // Ensure clickable
        };
        const hide = () => {

            modal.classList.remove('active');
            modal.style.display = 'none';
            modal.style.opacity = '0';
        };

        // Load Workspaces List
        API.listWorkspaces().then(data => {
            select.innerHTML = '<option value="">-- Select Workspace --</option>';
            (data.workspaces || []).forEach(s => {
                const opt = document.createElement('option');
                opt.value = s;
                opt.innerText = s;
                select.appendChild(opt);
            });
            show();
        }).catch(err => {
            console.error("Failed to list workspaces", err);
            // Even if listing fails, we MUST show the modal so user can try to create one or see the error
            select.innerHTML = '<option value="">Error loading workspaces</option>';
            Notifications.show("Could not list workspaces: " + err.message, "danger");
            show();
        });

        // Handlers
        btnLoad.onclick = () => {
            const name = select.value;
            if (!name) return Notifications.show("Please select a workspace", "danger");

            API.loadWorkspace(name).then(() => {
                hide();
                Notifications.show("Workspace Loaded", "success");
                if (onSuccess) onSuccess();
            }).catch(err => Notifications.show("Load Failed: " + err.message, "danger"));
        };

        if (btnDelete) {
            btnDelete.onclick = () => {
                const name = select.value;
                if (!name) return Notifications.show("Please select a workspace to delete", "warning");

                if (!confirm(`Are you sure you want to delete workspace "${name}"? This action cannot be undone.`)) {
                    return;
                }

                API.deleteWorkspace(name).then(() => {
                    Notifications.show("Workspace Deleted", "success");
                    // Refresh List
                    API.listWorkspaces().then(data => {
                        select.innerHTML = '<option value="">-- Select Workspace --</option>';
                        (data.workspaces || []).forEach(s => {
                            const opt = document.createElement('option');
                            opt.value = s;
                            opt.innerText = s;
                            select.appendChild(opt);
                        });
                    });
                }).catch(err => Notifications.show("Delete Failed: " + err.message, "danger"));
            };
        }

        btnCreate.onclick = () => {
            const name = inputNew.value.trim();
            if (!name) return Notifications.show("Enter a workspace name", "danger");

            API.createWorkspace(name).then(() => {
                hide();
                Notifications.show("Workspace Created", "success");
                if (onSuccess) onSuccess();
            }).catch(err => Notifications.show("Create Failed: " + err.message, "danger"));
        };
    }
}
