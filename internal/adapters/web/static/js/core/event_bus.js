/**
 * Event Bus
 * Simple Publish/Subscribe pattern for decoupling components.
 */

class EventBusImpl {
    constructor() {
        this.listeners = {};
    }

    /**
     * Subscribe to an event
     * @param {string} event - Event name
     * @param {function} callback - Callback function
     */
    on(event, callback) {
        if (!this.listeners[event]) {
            this.listeners[event] = [];
        }
        this.listeners[event].push(callback);
    }

    /**
     * Unsubscribe from an event
     * @param {string} event - Event name
     * @param {function} callback - Callback function to remove
     */
    off(event, callback) {
        if (!this.listeners[event]) return;
        this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
    }

    /**
     * Subscribe to an event once
     * @param {string} event - Event name
     * @param {function} callback - Callback function
     */
    once(event, callback) {
        const wrapper = (data) => {
            this.off(event, wrapper);
            callback(data);
        };
        this.on(event, wrapper);
    }

    /**
     * Emit an event
     * @param {string} event - Event name
     * @param {any} data - Data to pass to listeners
     */
    emit(event, data) {
        if (!this.listeners[event]) return;
        this.listeners[event].forEach(callback => {
            try {
                callback(data);
            } catch (err) {
                console.error(`Error in EventBus listener for "${event}":`, err);
            }
        });
    }
}

// Singleton instance
export const EventBus = new EventBusImpl();
