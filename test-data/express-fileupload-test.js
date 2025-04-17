// Test file for express-fileupload usage

const express = require('express');
const fileUpload = require('express-fileupload'); // Import library
const app = express();

// Use middleware without explicit limits
app.use(fileUpload());

app.post('/upload-express', (req, res) => {
  if (!req.files || Object.keys(req.files).length === 0) {
    return res.status(400).send('No files were uploaded.');
  }
  // Access files via req.files.yourInputFieldName
  res.send('Express file upload received');
});

app.listen(3002, () => console.log('Express-fileupload test server running')); 