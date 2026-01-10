/**
 * Shared Utility Functions
 */

export const Utils = {
    /**
     * Format bytes to human readable string
     * @param {number} bytes 
     * @param {number} decimals 
     * @returns {string}
     */
    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    },

    /**
     * Format date string to relative time
     * @param {string} dateString 
     * @returns {string}
     */
    timeAgo(dateString) {
        if (!dateString || dateString.startsWith('0001-01-01')) return 'Never';
        const date = new Date(dateString);
        if (isNaN(date.getTime())) return 'Unknown';

        const seconds = Math.floor((new Date() - date) / 1000);
        if (seconds < 60) return "Just now";

        let interval = seconds / 31536000;
        if (interval > 1) return Math.floor(interval) + " years ago";
        interval = seconds / 2592000;
        if (interval > 1) return Math.floor(interval) + " months ago";
        interval = seconds / 86400;
        if (interval > 1) return Math.floor(interval) + " days ago";
        interval = seconds / 3600;
        if (interval > 1) return Math.floor(interval) + " hours ago";
        interval = seconds / 60;
        if (interval > 1) return Math.floor(interval) + " mins ago";

        return Math.floor(seconds) + " seconds ago";
    }
};
