"use strict";
// @ts-nocheck
// Non-API Page: Sensitive name, but not an API route file (App Router)
// Should not be caught by Next.js API file-based check.
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = MetricsPage;
function MetricsPage() {
    return (<div>
      <h1>Metrics Dashboard (App Router Page)</h1>
      <p>This is a regular Next.js App Router page, not an API endpoint itself.</p>
    </div>);
}
