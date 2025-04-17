// Test config file

const apiKey = 'sk_live_THIS_IS_A_FAKE_STRIPE_KEY_PATTERNx01234567890ABC'; // Pattern might need adjustment

const settings = {
    retries: 3,
    // High entropy string, less likely to match simple patterns
    sessionSecret: 'ZghlMTU5YjEtYjYwMC00ZmRjLWFiMzEtOWQyZjc3MmVjZDBmCg==' 
};

function connect() {
    console.log('Connecting with key:', apiKey);
}

module.exports = { settings, connect }; 