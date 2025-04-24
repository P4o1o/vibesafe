const express = require('express');
const axios = require('axios'); // Assume axios is installed for testing http client scan

const app = express();
const port = 3000;

// Potentially exposed endpoint
app.get('/admin', (req, res) => {
  res.send('Admin Panel');
});

app.get('/data', async (req, res) => {
  try {
    // HTTP client call without timeout
    const response = await axios.get('https://jsonplaceholder.typicode.com/todos/1');
    res.json(response.data);
  } catch (error) {
    // Potential unsanitized error logging
    console.error(error);
    res.status(500).send('Error fetching data');
  }
});

app.listen(port, () => {
  console.log(`Test Express app listening at http://localhost:${port}`);
}); 