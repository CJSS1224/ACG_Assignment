/**
 * ST2504 Applied Cryptography - Socket Client
 * 
 * WebSocket connection management using Socket.IO.
 * 
 * Charles
 */

import { App } from '../core/state.js';
import { updateConnectionStatus } from '../ui/status.js';
import {
    handleUserOnline,
    handleUserOffline,
    handleOnlineUsersList,
    handleIncomingMessage,
    handleMessageSent,
    handleUserTyping,
    handleUserStopTyping,
    handleSocketError
} from './socket.handlers.js';

/**
 * Connect to WebSocket server
 */
export function connectWebSocket() {
    // Disconnect existing connection
    if (App.socket) {
        App.socket.disconnect();
    }

    updateConnectionStatus('connecting');

    // Create new connection with auth token
    App.socket = io({ query: { token: App.token } });

    // Connection events
    App.socket.on('connect', () => {
        console.log('[SOCKET] Connected');
        updateConnectionStatus('connected');
        App.socket.emit('get_online_users');
    });

    App.socket.on('disconnect', () => {
        console.log('[SOCKET] Disconnected');
        updateConnectionStatus('disconnected');
    });

    App.socket.on('connect_error', (error) => {
        console.error('[SOCKET] Connection error:', error);
        updateConnectionStatus('disconnected');
    });

    // User presence events
    App.socket.on('user_online', handleUserOnline);
    App.socket.on('user_offline', handleUserOffline);
    App.socket.on('online_users_list', handleOnlineUsersList);

    // Message events
    App.socket.on('new_message', handleIncomingMessage);
    App.socket.on('message_sent', handleMessageSent);

    // Typing events
    App.socket.on('user_typing', handleUserTyping);
    App.socket.on('user_stop_typing', handleUserStopTyping);

    // Error events
    App.socket.on('error', handleSocketError);
}

/**
 * Disconnect from WebSocket server
 */
export function disconnectWebSocket() {
    if (App.socket) {
        App.socket.disconnect();
        App.socket = null;
    }
}

/**
 * Emit send_message event
 */
export function emitSendMessage(recipientId, plaintext, privateKey) {
    if (App.socket) {
        App.socket.emit('send_message', {
            recipient_id: recipientId,
            plaintext,
            private_key: privateKey
        });
    }
}

/**
 * Emit typing indicator
 */
export function emitTyping(recipientId) {
    if (App.socket) {
        App.socket.emit('typing', { recipient_id: recipientId });
    }
}

/**
 * Emit stop typing indicator
 */
export function emitStopTyping(recipientId) {
    if (App.socket) {
        App.socket.emit('stop_typing', { recipient_id: recipientId });
    }
}

/**
 * Request online users list
 */
export function emitGetOnlineUsers() {
    if (App.socket) {
        App.socket.emit('get_online_users');
    }
}
