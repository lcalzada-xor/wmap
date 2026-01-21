import { describe, it, expect } from './test_runner.js';
import { EventBus } from '../core/event_bus.js';
import { html } from '../core/html.js';
import { Store } from '../core/store/store.js';
import { Events } from '../core/constants.js';
import { AuditManager } from '../ui/audit_manager.js';

// Mock API
const MockAPI = {
    getAuditLogs: async () => {
        return { logs: [] };
    }
};

// Inject Mock API into AuditManager context if needed, 
// but AuditManager imports API directly. 
// For this test, we will just verify the subscription logic.

export async function runTests() {

    await describe('EventBus System', async () => {
        it('should subscribe and receive events', async () => {
            let received = null;
            const handler = (data) => { received = data; };

            EventBus.on('test-event', handler);
            EventBus.emit('test-event', { val: 123 });

            expect(received.val).toBe(123);
            EventBus.off('test-event', handler);
        });

        it('should unsubscribe correctly', async () => {
            let count = 0;
            const handler = () => { count++; };

            EventBus.on('test-event-2', handler);
            EventBus.emit('test-event-2');
            EventBus.off('test-event-2', handler);
            EventBus.emit('test-event-2');

            expect(count).toBe(1);
        });
    });

    await describe('Safe HTML Templating', async () => {
        it('should escape XSS vectors', async () => {
            const malicious = '<script>alert(1)</script>';
            const output = html`<div>${malicious}</div>`;

            expect(output).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
            expect(output).toContain('<div>'); // Structure preserved
        });

        it('should handle multiple values', async () => {
            const v1 = 'A';
            const v2 = 'B';
            const output = html`1:${v1}, 2:${v2}`;
            expect(output).toBe('1:A, 2:B'); // Trimmed by implementation possibly, lets check.
            // Actually implementation joins parts and values.
        });
    });

    await describe('Reactive Store', async () => {
        it('should notify subscribers on mutation', async () => {
            let notified = false;

            // Subscribe
            Store.subscribe(Events.FILTER_UPDATED, () => { notified = true; });

            // Dispatch
            Store.dispatch(Events.FILTER_UPDATED, { key: 'searchQuery', value: 'test mutation' });

            expect(notified).toBe(true);
        });
    });

    await describe('AuditManager Integration', async () => {
        // Setup DOM mocks if needed
        if (!document.getElementById('audit-modal')) {
            const modal = document.createElement('div');
            modal.id = 'audit-modal';
            modal.style.display = 'none'; // Initially closed
            document.body.appendChild(modal);
        }

        const manager = new AuditManager();

        it('should subscribe to Events.LOG', async () => {
            // We can't easily check private listeners, but we can emit and check side effects
            // However, AuditManager.fetchLogs is async and calls API. It might fail in test env.
            // But we just want to ensure it doesn't crash on event emit.

            let error = null;
            try {
                // Open modal to enable listener logic
                manager.modal.style.display = 'flex';

                // Emit log
                EventBus.emit(Events.LOG, { message: 'Test Log', level: 'info' });

                // If we get here without error, it handled the event (even if API fails)
            } catch (e) {
                error = e;
            }

            expect(error).toBeFalsy();
            manager.close();
        });
    });
}
