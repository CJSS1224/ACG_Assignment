/**
 * ST2504 Applied Cryptography - Configuration
 * 
 * Application constants and configuration values.
 * 
 * Charles
 */

export const CONFIG = {
    // API endpoints
    API: {
        LOGIN: '/api/login',
        REGISTER: '/api/register',
        ME: '/api/me',
        CHATS: '/api/chats',
        USERS_ONLINE: '/api/users/online'
    },
    
    // Validation rules
    VALIDATION: {
        MIN_USERNAME_LENGTH: 3,
        MIN_PASSWORD_LENGTH: 6
    },
    
    // Timing
    TIMING: {
        TYPING_TIMEOUT: 1000,
        TOAST_DURATION: 3000,
        TOAST_FADE_DURATION: 300
    },
    
    // DOM element IDs
    SELECTORS: {
        // Containers
        AUTH_CONTAINER: 'auth-container',
        CHAT_CONTAINER: 'chat-container',
        MESSAGES_CONTAINER: 'messages-container',
        TOAST_CONTAINER: 'toast-container',
        CHAT_LIST: 'chat-list',
        
        // Forms
        LOGIN_FORM: 'login-form',
        REGISTER_FORM: 'register-form',
        
        // Inputs
        LOGIN_USERNAME: 'login-username',
        LOGIN_PASSWORD: 'login-password',
        REGISTER_USERNAME: 'register-username',
        REGISTER_PASSWORD: 'register-password',
        REGISTER_CONFIRM: 'register-confirm',
        MESSAGE_INPUT: 'message-input',
        
        // Buttons
        LOGOUT_BTN: 'logout-btn',
        NEW_CHAT_BTN: 'new-chat-btn',
        SEND_BTN: 'send-btn',
        CHAT_INFO_BTN: 'chat-info-btn',
        COPY_KEY_BTN: 'copy-key-btn',
        CLOSE_MODAL: 'close-modal',
        CLOSE_INFO_MODAL: 'close-info-modal',
        
        // Links
        SHOW_REGISTER: 'show-register',
        SHOW_LOGIN: 'show-login',
        
        // Modals
        NEW_CHAT_MODAL: 'new-chat-modal',
        CHAT_INFO_MODAL: 'chat-info-modal',
        ONLINE_USERS_LIST: 'online-users-list',
        
        // Chat interface
        NO_CHAT_SELECTED: 'no-chat-selected',
        ACTIVE_CHAT: 'active-chat',
        CHAT_USERNAME: 'chat-username',
        CHAT_STATUS: 'chat-status',
        TYPING_INDICATOR: 'typing-indicator',
        CURRENT_USERNAME: 'current-username',
        MY_PUBLIC_KEY: 'my-public-key'
    }
};

/**
 * Storage keys for localStorage
 */
export const STORAGE_KEYS = {
    AUTH_TOKEN: 'authToken',
    LOGGED_IN_USER: 'loggedInUser',
    PRIVATE_KEY: 'privateKey'
};
