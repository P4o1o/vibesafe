// Test file: Routes defined, and express-rate-limit IS imported

const express = require('express');
const rateLimit = require('express-rate-limit'); // Import the library
const app = express();

// Apply rate limiting (example configuration)
const limiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
	standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
	lazy: false, // Disable lazy loading
});

// Apply the rate limiting middleware to API calls only (example)
// Even though it's applied here, the scanner just checks for the import.
app.use('/api', limiter);

app.get('/api/data', (req, res) => {
  res.json({ data: 'some rate-limited data' });
});

app.post('/api/action', (req, res) => {
  res.send('Action processed (rate-limited)');
});

// Route outside the /api prefix (might not be rate-limited by above)
app.get('/non-api', (req, res) => {
    res.send('This might not be rate limited by the /api middleware');
});

app.listen(3006, () => console.log('Rate limit present test server running')); 