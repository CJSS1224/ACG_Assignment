/**
 * ST2504 Applied Cryptography - SecureChat Application
 * 
 * Main entrypoint for the modular SecureChat client.
 * 
 * This application implements end-to-end encryption:
 * - Server handles encryption (Python)
 * - Client handles decryption (JavaScript Web Crypto API)
 * - Messages are encrypted in transit and at rest
 * 
 * Charles
 */

import { CONFIG } from './core/config.js';
import { $ } from './ui/dom.js';

// Auth controller
import { 
    handleLogin, 
    handleRegister, 
    logout, 
    restoreSession,
    showRegisterForm,
    showLoginForm
} from './features/auth.controller.js';

// Chats controller
import { openChat } from './features/chats.controller.js';

// Messages controller
import { 
    sendMessage, 
    handleTypingInput, 
    handleMessageKeypress 
} from './features/messages.controller.js';

// Modal controller
import { 
    openNewChatModal, 
    closeNewChatModal, 
    showChatInfo, 
    closeChatInfoModal,
    copyPublicKey 
} from './features/modal.controller.js';

/**
 * Setup all event listeners
 */
function setupEventListeners() {
    // Auth form switching
    $(CONFIG.SELECTORS.SHOW_REGISTER)?.addEventListener('click', (e) => {
        e.preventDefault();
        showRegisterForm();
    });

    $(CONFIG.SELECTORS.SHOW_LOGIN)?.addEventListener('click', (e) => {
        e.preventDefault();
        showLoginForm();
    });

    // Login form
    $(CONFIG.SELECTORS.LOGIN_FORM)?.addEventListener('submit', (e) => {
        e.preventDefault();
        handleLogin();
    });

    // Register form
    $(CONFIG.SELECTORS.REGISTER_FORM)?.addEventListener('submit', (e) => {
        e.preventDefault();
        handleRegister();
    });

    // Logout
    $(CONFIG.SELECTORS.LOGOUT_BTN)?.addEventListener('click', logout);

    // New chat modal
    $(CONFIG.SELECTORS.NEW_CHAT_BTN)?.addEventListener('click', openNewChatModal);
    $(CONFIG.SELECTORS.CLOSE_MODAL)?.addEventListener('click', closeNewChatModal);

    // Chat info modal
    $(CONFIG.SELECTORS.CHAT_INFO_BTN)?.addEventListener('click', showChatInfo);
    $(CONFIG.SELECTORS.CLOSE_INFO_MODAL)?.addEventListener('click', closeChatInfoModal);

    // Copy public key
    $(CONFIG.SELECTORS.COPY_KEY_BTN)?.addEventListener('click', copyPublicKey);

    // Message input
    const messageInput = $(CONFIG.SELECTORS.MESSAGE_INPUT);
    if (messageInput) {
        messageInput.addEventListener('keypress', handleMessageKeypress);
        messageInput.addEventListener('input', handleTypingInput);
    }

    // Send button
    $(CONFIG.SELECTORS.SEND_BTN)?.addEventListener('click', sendMessage);

    // Modal backdrop clicks
    $(CONFIG.SELECTORS.NEW_CHAT_MODAL)?.addEventListener('click', (e) => {
        if (e.target.id === CONFIG.SELECTORS.NEW_CHAT_MODAL) {
            closeNewChatModal();
        }
    });
    
    $(CONFIG.SELECTORS.CHAT_INFO_MODAL)?.addEventListener('click', (e) => {
        if (e.target.id === CONFIG.SELECTORS.CHAT_INFO_MODAL) {
            closeChatInfoModal();
        }
    });
}

/**
 * Expose functions to global scope for inline onclick handlers
 * This is needed for onclick attributes in dynamically rendered HTML
 */
function exposeGlobalFunctions() {
    window.SecureChat = {
        openChat,
        openNewChatModal,
        sendMessage
    };
}

/**
 * Initialize the application
 */
async function init() {
    console.log('[APP] Initializing SecureChat (Modular)...');
    
    // Setup event listeners
    setupEventListeners();
    
    // Expose global functions for HTML onclick handlers
    exposeGlobalFunctions();
    
    // Try to restore existing session
    await restoreSession();
    
    console.log('[APP] Initialization complete');
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', init);
