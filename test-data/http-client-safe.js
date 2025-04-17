// Test file for HTTP client calls with timeouts/signals

const axios = require('axios');
// Assume fetch and AbortController are available globally or polyfilled

async function safeFetch() {
    console.log('Making safe fetch call...');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000); // 5 second timeout

    try {
        // fetch call with signal
        const response = await fetch('https://httpbin.org/delay/3', { signal: controller.signal }); 
        const data = await response.json();
        console.log('Safe fetch success:', data);
    } catch (error) {
        if (error.name === 'AbortError') {
            console.error('Safe fetch timed out!');
        } else {
            console.error('Safe fetch failed:', error.message);
        }
    } finally {
        clearTimeout(timeoutId);
    }
}

async function safeAxios() {
    console.log('Making safe axios calls...');
    const controller = new AbortController();

    try {
        // axios.get with timeout
        const res1 = await axios.get('https://httpbin.org/delay/3', { timeout: 5000 });
        console.log('Safe axios.get success (timeout):', res1.data);

        // axios.post with AbortController signal
        const res2 = await axios.post('https://httpbin.org/post', 
            { name: 'vibesafe' }, 
            { signal: controller.signal } // Config object with signal
        );
        console.log('Safe axios.post success (signal):', res2.data);

         // axios direct call with timeout
        const res3 = await axios({
            method: 'get',
            url: 'https://httpbin.org/delay/3',
            timeout: 5000 // Timeout directly in config
        });
        console.log('Safe axios direct success (timeout):', res3.data);

    } catch (error) {
        if (axios.isCancel(error)) {
             console.error('Safe axios request cancelled:', error.message);
        } else if (error.code === 'ECONNABORTED') {
            console.error('Safe axios request timed out.');
        } else {
            console.error('Safe axios failed:', error.message);
        }
    }
}

safeFetch();
safeAxios();

// --- New safe examples ---
const got = require('got'); // Assuming got is installed
const superagent = require('superagent'); // Assuming superagent is installed
const request = require('request'); // Assuming request is installed (deprecated)

async function safeGot() {
    console.log('Making safe got calls...');
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
        // got call with timeout option
        const res1 = await got('https://httpbin.org/delay/3', { timeout: { request: 5000 } });
        console.log('Safe got success (timeout):', res1.body);

        // got.post with AbortController signal
        const res2 = await got.post('https://httpbin.org/post', {
            json: { name: 'vibesafe' },
            responseType: 'json',
            signal: controller.signal // Using AbortController signal
        });
        console.log('Safe got.post success (signal):', res2.body);
    } catch (error) {
        if (error.name === 'TimeoutError') {
             console.error('Safe got timed out!');
        } else if (error.name === 'AbortError') {
             console.error('Safe got aborted (signal)!');
        } else {
            console.error('Safe got failed:', error.message);
        }
    } finally {
         clearTimeout(timeoutId); // Clear timeout if signal was used
    }
}

async function safeSuperagent() {
    console.log('Making safe superagent calls...');
    try {
        // superagent call with chained .timeout()
        const res1 = await superagent.get('https://httpbin.org/delay/3').timeout({ response: 5000, deadline: 6000 });
        console.log('Safe superagent.get success (timeout):', res1.body);

        // superagent call with .timeout() in the chain
        const res2 = await superagent
            .post('https://httpbin.org/post')
            .send({ name: 'vibesafe' })
            .set('accept', 'json')
            .timeout(5000); // Simple timeout
        console.log('Safe superagent.post success (timeout):', res2.body);
    } catch (error) {
         if (error.timeout) { // Superagent specific timeout property
             console.error('Safe superagent timed out!');
         } else {
            console.error('Safe superagent failed:', error.message);
         }
    }
}

function safeRequest() {
    console.log('Making safe request calls...');
    // request with timeout option
    request('https://httpbin.org/delay/3', { timeout: 5000 }, (error, response, body) => {
        if (error) {
            if (error.code === 'ETIMEDOUT' || error.code === 'ESOCKETTIMEDOUT') {
                 console.error('Safe request timed out (callback)!');
            } else {
                 console.error('Safe request failed (callback):', error);
            }
        } else {
            console.log('Safe request success (callback):', body.substring(0, 50));
        }
    });

    // request.get with timeout option
    request.get('https://httpbin.org/get', { timeout: 5000, json: true }, (error, response, body) => {
        if (error) {
             if (error.code === 'ETIMEDOUT' || error.code === 'ESOCKETTIMEDOUT') {
                 console.error('Safe request.get timed out (callback)!');
            } else {
                 console.error('Safe request.get failed (callback):', error);
            }
        } else {
            console.log('Safe request.get success (callback):', body);
        }
    });
}

safeGot();
safeSuperagent();
safeRequest(); 