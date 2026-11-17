'use strict';

// Gêmea limpa de P-007 e P-008: segredos vêm do ambiente.
const config = { host: process.env.DB_HOST, user: process.env.DB_USER, password: process.env.DB_PASSWORD };

module.exports = { config };
