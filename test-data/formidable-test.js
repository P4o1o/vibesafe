// Test file for formidable usage without maxFileSize

const http = require('http');
const { Formidable } = require('formidable'); // Import Formidable

const server = http.createServer((req, res) => {
  if (req.url === '/upload-formidable' && req.method.toLowerCase() === 'post') {
    // Initialize Formidable without maxFileSize
    const form = new Formidable({}); 

    form.parse(req, (err, fields, files) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error parsing form');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ fields, files }, null, 2));
    });
    return;
  }

  // Default response for other requests
  res.writeHead(404);
  res.end();
});

server.listen(3003, () => {
  console.log('Formidable test server running');
}); 