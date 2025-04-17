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

// --- Test cases for PII logging --- 
function processUserData(user) {
    try {
        console.log(`Processing user: ${user.id}`); // Safe
        
        // Potentially unsafe logging
        console.log('User data:', user); // Logging the whole user object
        logger.info('User details', { email: user.email, name: user.name }); // Logging PII
        console.debug('User session token:', user.sessionToken); // Logging sensitive token
        console.warn("Auth credentials for user:", user.credentials); // Logging credentials
        
        // Safe logging
        logger.info('Processed user ID:', user.id); 
        console.log('User processing complete for ID', user.id);

        if (!user.email) throw new Error('User email missing');

    } catch (error) {
        // Logging error is handled above, but PII check might still trigger here if error contains PII
        console.error('Error processing user:', error);
    }
}

const sampleUser = {
    id: 'user123',
    name: 'Test User',
    email: 'test.user@example.com',
    password: 'supersecretpassword', // Example field
    sessionToken: 'abc123xyz789token', // Example field
    credentials: { apiKey: 'cred_1234567890abcdef' } // Example field
};

processUserData(sampleUser);

app.listen(3007, () => console.log('Logging test server running')); 