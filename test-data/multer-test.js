// Test file for multer usage without limits/filter

const express = require('express');
const multer = require('multer'); // Import multer
const app = express();

// Initialize multer without any options
const upload = multer(); 

app.post('/profile-basic', upload.single('avatar'), (req, res) => {
  // Handle file upload
  res.send('Basic upload received');
});

// Initialize with empty options object
const uploadEmptyOptions = multer({}); 

app.post('/profile-empty', uploadEmptyOptions.single('avatar'), (req, res) => {
  // Handle file upload
  res.send('Empty options upload received');
});

app.listen(3001, () => console.log('Multer test server running')); 