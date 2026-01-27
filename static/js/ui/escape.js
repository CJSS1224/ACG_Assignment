/**
 * ST2504 Applied Cryptography - HTML Escape Utility
 * 
 * Charles
 */

/**
 * Escape HTML special characters to prevent XSS
 * @param {string} text 
 * @returns {string}
 */
export function escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
