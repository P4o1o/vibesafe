// Test file for HTTP client calls potentially missing timeouts

const axios = require('axios');
// Assume fetch is available globally or polyfilled

async function unsafeFetch() {
    console.log('Making unsafe fetch call...');
    try {
        // fetch call without options object or signal
        const response = await fetch('https://httpbin.org/delay/5'); 
        const data = await response.json();
        console.log('Unsafe fetch success:', data);
    } catch (error) {
        // We are testing the call site, not the error handling logging here
        console.error('Unsafe fetch failed:', error.message);
    }
}

async function unsafeAxios() {
    console.log('Making unsafe axios calls...');
    try {
        // axios.get without config object
        const res1 = await axios.get('https://httpbin.org/delay/5');
        console.log('Unsafe axios.get success:', res1.data);

        // axios.post with data but no config object
        const res2 = await axios.post('https://httpbin.org/post', { name: 'vibesafe' });
        console.log('Unsafe axios.post success:', res2.data);

         // axios direct call with config object, but no timeout/signal
        const res3 = await axios({
            method: 'get',
            url: 'https://httpbin.org/delay/5',
            headers: { 'Accept': 'application/json' }
        });
        console.log('Unsafe axios direct success:', res3.data);

    } catch (error) {
        console.error('Unsafe axios failed:', error.message);
    }
}

unsafeFetch();
unsafeAxios();

// --- New unsafe examples ---
const got = require('got'); // Assuming got is installed
const superagent = require('superagent'); // Assuming superagent is installed
const request = require('request'); // Assuming request is installed (deprecated)

async function unsafeGot() {
    console.log('Making unsafe got calls...');
    try {
        // got call without options object
        const res1 = await got('https://httpbin.org/delay/5');
        console.log('Unsafe got success:', res1.body);

        // got.post with options, but no timeout/signal
        const res2 = await got.post('https://httpbin.org/post', { json: { name: 'vibesafe' }, responseType: 'json' });
        console.log('Unsafe got.post success:', res2.body);
    } catch (error) {
        console.error('Unsafe got failed:', error.message);
    }
}

async function unsafeSuperagent() {
    console.log('Making unsafe superagent calls...');
    try {
        // superagent call without chained .timeout()
        const res1 = await superagent.get('https://httpbin.org/delay/5');
        console.log('Unsafe superagent.get success:', res1.body);

        // superagent call with some chaining, but still no .timeout()
        const res2 = await superagent.post('https://httpbin.org/post').send({ name: 'vibesafe' }).set('accept', 'json');
        console.log('Unsafe superagent.post success:', res2.body);
    } catch (error) {
        console.error('Unsafe superagent failed:', error.message);
    }
}

function unsafeRequest() {
    console.log('Making unsafe request calls...');
    // request without options object
    request('https://httpbin.org/delay/5', (error, response, body) => {
        if (error) console.error('Unsafe request failed:', error);
        else console.log('Unsafe request success (callback):', body.substring(0, 50));
    });

    // request.get with options, but no timeout
    request.get('https://httpbin.org/delay/5', { json: true }, (error, response, body) => {
        if (error) console.error('Unsafe request.get failed:', error);
        else console.log('Unsafe request.get success (callback):', body);
    });
}

unsafeGot();
unsafeSuperagent();
unsafeRequest(); 