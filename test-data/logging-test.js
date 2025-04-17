// Test file for improper error logging

const express = require('express');
const app = express();

// Assume a generic logger instance exists
const logger = { 
    error: (msg) => console.error('[Logger] Error:', msg),
    warn: (msg) => console.warn('[Logger] Warn:', msg),
    info: (msg) => console.info('[Logger] Info:', msg)
};

app.get('/process/:id', (req, res) => {
    try {
        if (req.params.id === 'fail') {
            throw new Error('Processing failed for ID ' + req.params.id);
        }
        res.send('Processed successfully');
    } catch (err) { // Common variable name 'err'
        // --- Patterns scanner should detect --- 
        console.error(err); // Logging the full error object to console.error
        logger.error(err); // Logging the full error object using a logger variable
        console.log(err); // Logging full error object to console.log (less common but possible)

        // --- Patterns scanner should *ideally* ignore --- 
        console.error('Error processing request:', err.message); // Logging only the message (Good practice)
        console.error(`Request failed for ${req.params.id}`); // Logging a string literal (Safe)
        logger.error({ errorId: 'xyz', message: err.message }); // Logging a structured, sanitized object (Good practice)

        res.status(500).send('Internal Server Error');
    }
});

function anotherFunction() {
    try {
        // Some operation that might fail
        throw new Error('Something went wrong in another function');
    } catch (e) { // Common variable name 'e'
        // --- Pattern scanner should detect --- 
        logger.warn(e); // Logging full error 'e' using logger.warn
    }
}

function yetAnotherFunction() {
    try {
        // Some operation
    } catch (error) { // Common variable name 'error'
         // --- Pattern scanner should detect --- 
        console.log(error);
    }
}

anotherFunction();
yetAnotherFunction();

app.listen(3007, () => console.log('Logging test server running')); 