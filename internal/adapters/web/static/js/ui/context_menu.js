import { API } from '../core/api.js';
import { Notifications } from './notifications.js';
import { Modals } from './modals.js';

export class ContextMenu {
    constructor(network, nodesDataSet) {
        this.network = network;
        this.nodes = nodesDataSet;
        this.ctxMenu = document.getElementById('context-menu');
        this.customActions = new Map();
    }

    init() {
        this.network.on("oncontext", (p) => {
            p.event.preventDefault();
            const nodeId = this.network.getNodeAt(p.pointer.DOM);

            if (nodeId) {
                this.network.selectNodes([nodeId]);
                if (this.ctxMenu) {
                    this.ctxMenu.style.display = 'block';
                    this.ctxMenu.style.left = p.pointer.DOM.x + 'px';
                    this.ctxMenu.style.top = p.pointer.DOM.y + 'px';
                    this.ctxMenu.dataset.targetId = nodeId;

                    // Bind actions if not already bound
                    if (!this.ctxMenu.hasAttribute('data-bound')) {
                        this.ctxMenu.querySelectorAll('.menu-item').forEach(item => {
                            item.onclick = (e) => {
                                const action = item.dataset.action;
                                const target = this.ctxMenu.dataset.targetId;
                                this.handleContextAction(action, target);
                                this.ctxMenu.style.display = 'none';
                                e.stopPropagation();
                            };
                        });
                        this.ctxMenu.setAttribute('data-bound', 'true');
                    }
                }
            }
        });

        // Global click to close
        this.network.on("click", () => {
            if (this.ctxMenu) this.ctxMenu.style.display = 'none';
        });
    }

    addAction(actionName, label, callback) {

        this.customActions.set(actionName, callback);
        // We assume the HTML element already exists or we might need to dynamically create it?
        // For now, the 'deauth' item is already in HTML.
        // If we wanted dynamic items, we'd need to append to DOM.
        // Let's assume the element exists for now as per main.js init.
    }

    handleContextAction(action, nodeId) {
        const node = this.nodes.get(nodeId);
        if (!node) return;

        // Check custom actions first
        if (this.customActions.has(action)) {
            this.customActions.get(action)(nodeId);
            return;
        }

        switch (action) {
            case 'focus':
                this.network.focus(nodeId, {
                    scale: 1.5,
                    animation: { duration: 1000, easingFunction: 'easeInOutQuad' }
                });
                break;
            case 'alias':
                Modals.prompt("Rename Device", (val) => {
                    if (val) API.setAlias(node.id, val).then(() => {
                        Notifications.show(`Alias set to ${val}`, "success");
                        // Optimistic update
                        this.nodes.update({ id: nodeId, label: val });
                    });
                });
                break;
            case 'copy':
                navigator.clipboard.writeText(node.id).then(() => {
                    Notifications.show("MAC Address Copied", "success");
                });
                break;
            case 'details':
                Notifications.show("Details Panel logic pending...", "warning");
                break;
        }
    }
}
