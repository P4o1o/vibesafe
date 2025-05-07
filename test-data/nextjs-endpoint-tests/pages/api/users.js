"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = handler;
// @ts-nocheck
// Non-sensitive: pages/api route
function handler(req, res) {
    res.status(200).json({ message: 'Users API endpoint' });
}
