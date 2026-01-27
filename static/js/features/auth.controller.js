/**
 * ST2504 Applied Cryptography - Auth Controller
 * 
 * Handles login, registration, logout, and session restoration.
 * 
 * Charles
 */

import { App, setAuthData, resetState } from '../core/state.js';
import { CONFIG } from '../core/config.js';
import { saveSession, clearSession, getStoredSession } from '../core/storage.js';
import { login, register, verifyToken } from '../api/auth.api.js';
import { connectWebSocket, disconnectWebSocket } from '../socket/socket.client.js';
import { showToast } from '../ui/toast.js';
import { $, show, hide, getValue, resetForm, setText, toggleClass } from '../ui/dom.js';
import { loadChats } from './chats.controller.js';

/**
 * Show the chat interface after successful auth
 */
function showChatInterface() {
    hide(CONFIG.SELECTORS.AUTH_CONTAINER);
    show(CONFIG.SELECTORS.CHAT_CONTAINER);
    setText(CONFIG.SELECTORS.CURRENT_USERNAME, App.user.username);
    loadChats();
}

/**
 * Show the auth interface
 */
function showAuthInterface() {
    show(CONFIG.SELECTORS.AUTH_CONTAINER);
    hide(CONFIG.SELECTORS.CHAT_CONTAINER);
    
    resetForm(CONFIG.SELECTORS.LOGIN_FORM);
    resetForm(CONFIG.SELECTORS.REGISTER_FORM);
    
    const loginForm = $(CONFIG.SELECTORS.LOGIN_FORM);
    const registerForm = $(CONFIG.SELECTORS.REGISTER_FORM);
    
    if (loginForm) loginForm.classList.add('active');
    if (registerForm) registerForm.classList.remove('active');
}

/**
 * Handle login form submission
 */
export async function handleLogin() {
    const username = getValue(CONFIG.SELECTORS.LOGIN_USERNAME);
    const password = $(CONFIG.SELECTORS.LOGIN_PASSWORD)?.value || '';

    if (!username || !password) {
        showToast('Please enter username and password', 'error');
        return;
    }

    try {
        const response = await login(username, password);

        if (!response.ok) {
            showToast(response.data.error || 'Login failed', 'error');
            return;
        }

        const data = response.data;

        // Check if server returned private key
        if (!data.private_key) {
            showToast('Failed to retrieve private key from server', 'error');
            return;
        }

        // Store session
        setAuthData(data.token, data.user, data.private_key);
        saveSession(data.token, data.user, data.private_key);

        showToast('Login successful!', 'success');
        showChatInterface();
        connectWebSocket();

    } catch (error) {
        console.error('[AUTH] Login error:', error);
        showToast('An error occurred during login', 'error');
    }
}

/**
 * Handle registration form submission
 */
export async function handleRegister() {
    const username = getValue(CONFIG.SELECTORS.REGISTER_USERNAME);
    const password = $(CONFIG.SELECTORS.REGISTER_PASSWORD)?.value || '';
    const confirm = $(CONFIG.SELECTORS.REGISTER_CONFIRM)?.value || '';

    if (!username || username.length < CONFIG.VALIDATION.MIN_USERNAME_LENGTH) {
        showToast(`Username must be at least ${CONFIG.VALIDATION.MIN_USERNAME_LENGTH} characters`, 'error');
        return;
    }

    if (!password || password.length < CONFIG.VALIDATION.MIN_PASSWORD_LENGTH) {
        showToast(`Password must be at least ${CONFIG.VALIDATION.MIN_PASSWORD_LENGTH} characters`, 'error');
        return;
    }

    if (password !== confirm) {
        showToast('Passwords do not match', 'error');
        return;
    }

    try {
        const response = await register(username, password);

        if (!response.ok) {
            showToast(response.data.error || 'Registration failed', 'error');
            return;
        }

        const data = response.data;

        // Store session and private key
        const user = {
            id: data.user_id,
            username: data.username,
            public_key: data.public_key
        };
        
        setAuthData(data.token, user, data.private_key);
        saveSession(data.token, user, data.private_key);

        showToast('Registration successful!', 'success');
        showChatInterface();
        connectWebSocket();

    } catch (error) {
        console.error('[AUTH] Registration error:', error);
        showToast('An error occurred during registration', 'error');
    }
}

/**
 * Handle logout
 */
export function logout() {
    disconnectWebSocket();
    resetState();
    clearSession();
    showAuthInterface();
    showToast('Logged out successfully', 'success');
}

/**
 * Restore session from storage on page load
 */
export async function restoreSession() {
    const stored = getStoredSession();
    
    if (stored.token && stored.user && stored.privateKey) {
        setAuthData(stored.token, stored.user, stored.privateKey);
        
        // Verify token is still valid
        const isValid = await verifyToken();
        
        if (isValid) {
            showChatInterface();
            connectWebSocket();
            return true;
        } else {
            logout();
            return false;
        }
    }
    
    return false;
}

/**
 * Switch to register form
 */
export function showRegisterForm() {
    $(CONFIG.SELECTORS.LOGIN_FORM)?.classList.remove('active');
    $(CONFIG.SELECTORS.REGISTER_FORM)?.classList.add('active');
}

/**
 * Switch to login form
 */
export function showLoginForm() {
    $(CONFIG.SELECTORS.REGISTER_FORM)?.classList.remove('active');
    $(CONFIG.SELECTORS.LOGIN_FORM)?.classList.add('active');
}
