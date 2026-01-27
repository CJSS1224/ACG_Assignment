/**
 * ST2504 Applied Cryptography - DOM Helpers
 * 
 * Utilities for DOM manipulation and element caching.
 * 
 * Charles
 */

import { CONFIG } from '../core/config.js';

// Element cache
const elementCache = new Map();

/**
 * Get element by ID with caching
 * @param {string} id 
 * @returns {HTMLElement|null}
 */
export function $(id) {
    if (!elementCache.has(id)) {
        elementCache.set(id, document.getElementById(id));
    }
    return elementCache.get(id);
}

/**
 * Clear element cache (call after DOM changes)
 */
export function clearCache() {
    elementCache.clear();
}

/**
 * Show an element by removing 'hidden' class
 * @param {string} id 
 */
export function show(id) {
    const el = $(id);
    if (el) el.classList.remove('hidden');
}

/**
 * Hide an element by adding 'hidden' class
 * @param {string} id 
 */
export function hide(id) {
    const el = $(id);
    if (el) el.classList.add('hidden');
}

/**
 * Toggle element visibility
 * @param {string} id 
 * @param {boolean} visible 
 */
export function toggle(id, visible) {
    if (visible) {
        show(id);
    } else {
        hide(id);
    }
}

/**
 * Set element text content
 * @param {string} id 
 * @param {string} text 
 */
export function setText(id, text) {
    const el = $(id);
    if (el) el.textContent = text;
}

/**
 * Set element innerHTML
 * @param {string} id 
 * @param {string} html 
 */
export function setHtml(id, html) {
    const el = $(id);
    if (el) el.innerHTML = html;
}

/**
 * Get input value
 * @param {string} id 
 * @returns {string}
 */
export function getValue(id) {
    const el = $(id);
    return el ? el.value.trim() : '';
}

/**
 * Set input value
 * @param {string} id 
 * @param {string} value 
 */
export function setValue(id, value) {
    const el = $(id);
    if (el) el.value = value;
}

/**
 * Add event listener to element
 * @param {string} id 
 * @param {string} event 
 * @param {Function} handler 
 */
export function on(id, event, handler) {
    const el = $(id);
    if (el) el.addEventListener(event, handler);
}

/**
 * Add/remove class based on condition
 * @param {string} id 
 * @param {string} className 
 * @param {boolean} condition 
 */
export function toggleClass(id, className, condition) {
    const el = $(id);
    if (el) el.classList.toggle(className, condition);
}

/**
 * Focus on element
 * @param {string} id 
 */
export function focus(id) {
    const el = $(id);
    if (el) el.focus();
}

/**
 * Reset form element
 * @param {string} id 
 */
export function resetForm(id) {
    const el = $(id);
    if (el && el.reset) el.reset();
}
