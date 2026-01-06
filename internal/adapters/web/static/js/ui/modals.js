/**
 * Modal Manager
 * Facade for specific modal modules.
 */

import { SessionModal } from './modals/session_modal.js';
import { ChannelModal } from './modals/channel_modal.js';

export const Modals = {
    // Session Modal
    initSessionModal(onSuccess) {
        SessionModal.init(onSuccess);
    },

    // Channel Config Modal
    initChannelModal() {
        ChannelModal.init();
    },

    // Generic Input Modal (Alias)
    prompt(title, callback) {
        const modal = document.getElementById('custom-modal');
        const mTitle = document.getElementById('modal-title');
        const mInput = document.getElementById('modal-input');
        const btnCancel = document.getElementById('btn-modal-cancel');
        const btnConfirm = document.getElementById('btn-modal-confirm');

        mTitle.innerText = title;
        mInput.value = '';

        modal.classList.add('active'); // CSS Transition

        // Auto-focus slightly delayed to account for animation
        setTimeout(() => mInput.focus(), 100);

        const close = () => {
            modal.classList.remove('active');
            btnConfirm.onclick = null;
            btnCancel.onclick = null;
        };

        btnConfirm.onclick = () => {
            const val = mInput.value.trim();
            close();
            callback(val);
        };

        btnCancel.onclick = () => {
            close();
            callback(null);
        };
    }
};
