// Test file for potentially exposed endpoints

const express = require('express');
const app = express();
const router = express.Router();

// Example admin route
app.get('/admin/users', (req, res) => {
    // Should be protected!
    res.send('Admin users page');
});

// Example debug route on a router
router.use('/debug/data', (req, res, next) => {
    // Should be protected or removed for production
    res.json({ debugInfo: 'some data' });
});

// Example status endpoint
app.post('/status', (req, res) => {
    res.send('App is running');
});

// Simple string literal containing a sensitive path
function getInfo() {
    const infoPath = '/info'; // Lower severity finding expected
    // ... some logic using infoPath
    return `Access info at ${infoPath}`;
}

// Another string literal
const metricsUrl = "/metrics";

// Mount the router
app.use('/api', router); // Prefixing the router path

app.listen(3004, () => console.log('Endpoint test server running')); 