import { startConnectionStatus } from './components/connection-status.js';

const connection = document.querySelector('#connection-status');
if (connection) startConnectionStatus(connection);
