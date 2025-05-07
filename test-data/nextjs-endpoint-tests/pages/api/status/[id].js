"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = handler;
// Sensitive: Dynamic pages/api route
function handler(req, res) {
    const { id } = req.query;
    res.status(200).json({ message: `Status for ID: ${id}` });
}
