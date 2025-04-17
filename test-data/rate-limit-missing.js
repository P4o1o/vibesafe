// Test file: Routes defined, but express-rate-limit is MISSING

const express = require('express');
const app = express();

// No import for express-rate-limit here!

app.get('/api/public-data', (req, res) => {
  // This endpoint might be okay without rate limiting, 
  // but the scanner should flag the file as potentially missing it.
  res.json({ data: 'some public info' });
});

app.post('/api/login', (req, res) => {
  // This endpoint SHOULD definitely have rate limiting!
  // The scanner will flag this file.
  res.send('Login attempt processed');
});

app.use('/api/users/:id', (req, res) => {
    res.send(`User data for ${req.params.id}`)
})

app.listen(3005, () => console.log('Rate limit missing test server running')); 