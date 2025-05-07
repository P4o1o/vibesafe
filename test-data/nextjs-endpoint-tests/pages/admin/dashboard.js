"use strict";
// @ts-nocheck
// Non-API Page: Sensitive name, but not an API route file
// Should not be caught by Next.js API file-based check
// May be caught by general regex if content matches, e.g. const apiUrl = '/api/admin/data';
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = AdminDashboardPage;
function AdminDashboardPage() {
    return (<div>
      <h1>Admin Dashboard</h1>
      <p>This is a regular Next.js page, not an API endpoint itself.</p>
      {/* Example that might trigger regex: <a href="/api/admin/settings">Settings</a> */}
    </div>);
}
