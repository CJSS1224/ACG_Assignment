/**
 * UI Utilities Module - Member 2
 * 
 * Handles UI-related utility functions:
 * - Toast notifications
 * - HTML escaping (XSS prevention)
 * - Element visibility
 * - Connection status
 */

const UI = {
    /**
     * Show a toast notification
     * @param {string} message - Message to display
     * @param {string} type - 'success', 'error', or 'warning'
     */
    showToast(message, type = 'success') {
        const container = document.getElementById('toast-container');
        
        const icons = {
            success: 'fa-check-circle',
            error: 'fa-exclamation-circle',
            warning: 'fa-exclamation-triangle'
        };

        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <i class="fas ${icons[type] || icons.success}"></i>
            <span>${this.escapeHtml(message)}</span>
        `;

        container.appendChild(toast);

        // Remove after 3 seconds
        setTimeout(() => {
            toast.style.animation = 'fadeOut 0.3s ease forwards';
            setTimeout(() => toast.remove(), 300);
        }, 3000);
    },

    /**
     * Escape HTML to prevent XSS attacks
     * @param {string} text - Text to escape
     * @returns {string} Escaped HTML-safe text
     */
    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    },

    /**
     * Format timestamp for display
     * @param {string} timestamp - ISO timestamp string
     * @returns {string} Formatted time (e.g., "2:30 PM")
     */
    formatTime(timestamp) {
        if (!timestamp) return 'Now';
        const date = new Date(timestamp);
        if (isNaN(date.getTime())) return 'Now';
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    },

    /**
     * Show an element by removing 'hidden' class
     * @param {string|HTMLElement} elementOrId - Element or ID
     */
    show(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) el.classList.remove('hidden');
    },

    /**
     * Hide an element by adding 'hidden' class
     * @param {string|HTMLElement} elementOrId - Element or ID
     */
    hide(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) el.classList.add('hidden');
    },

    /**
     * Update connection status indicator
     * @param {string} status - 'connected', 'disconnected', or 'connecting'
     */
    updateConnectionStatus(status) {
        const statusDot = document.querySelector('.status-dot');
        const statusText = document.querySelector('.status-text');

        statusDot.classList.remove('connected', 'disconnected');
        
        switch (status) {
            case 'connected':
                statusDot.classList.add('connected');
                statusText.textContent = 'Connected';
                break;
            case 'disconnected':
                statusDot.classList.add('disconnected');
                statusText.textContent = 'Disconnected';
                break;
            default:
                statusText.textContent = 'Connecting...';
        }
    },

    /**
     * Scroll an element to the bottom
     * @param {string|HTMLElement} elementOrId - Element or ID
     */
    scrollToBottom(elementOrId) {
        const el = typeof elementOrId === 'string' 
            ? document.getElementById(elementOrId) 
            : elementOrId;
        if (el) el.scrollTop = el.scrollHeight;
    }
};

// Export for use in other modules
window.UI = UI;
