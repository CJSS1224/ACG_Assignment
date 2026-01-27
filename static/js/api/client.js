/**
 * ST2504 Applied Cryptography - API Client
 * 
 * Fetch wrapper that automatically adds Authorization headers.
 * 
 * Charles
 */

import { App } from '../core/state.js';

/**
 * Make an authenticated GET request
 */
export async function get(url) {
    const response = await fetch(url, {
        method: 'GET',
        headers: getHeaders()
    });
    return handleResponse(response);
}

/**
 * Make an authenticated POST request
 */
export async function post(url, data = {}) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            ...getHeaders(),
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    return handleResponse(response);
}

/**
 * Make an unauthenticated POST request (for login/register)
 */
export async function postPublic(url, data = {}) {
    const response = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    });
    return handleResponse(response);
}

/**
 * Get default headers with auth token
 */
function getHeaders() {
    const headers = {};
    if (App.token) {
        headers['Authorization'] = `Bearer ${App.token}`;
    }
    return headers;
}

/**
 * Handle API response
 */
async function handleResponse(response) {
    const data = await response.json();
    return {
        ok: response.ok,
        status: response.status,
        data
    };
}
