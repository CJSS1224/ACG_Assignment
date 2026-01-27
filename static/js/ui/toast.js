/**
 * ST2504 Applied Cryptography - Toast Notifications
 * 
 * Charles
 */

import { CONFIG } from '../core/config.js';
import { $ } from './dom.js';
import { escapeHtml } from './escape.js';

const ICONS = {
    success: 'fa-check-circle',
    error: 'fa-exclamation-circle',
    warning: 'fa-exclamation-triangle'
};

/**
 * Show a toast notification
 * @param {string} message 
 * @param {string} type - 'success' | 'error' | 'warning'
 */
export function showToast(message, type = 'success') {
    const container = $(CONFIG.SELECTORS.TOAST_CONTAINER);
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
        <i class="fas ${ICONS[type] || ICONS.success}"></i>
        <span>${escapeHtml(message)}</span>
    `;

    container.appendChild(toast);

    // Auto-remove after duration
    setTimeout(() => {
        toast.style.animation = 'fadeOut 0.3s ease forwards';
        setTimeout(() => toast.remove(), CONFIG.TIMING.TOAST_FADE_DURATION);
    }, CONFIG.TIMING.TOAST_DURATION);
}
