// Test file for superagent HTTP client calls
// Note: The current scanner flags all superagent calls as potentially missing
//       timeouts because checking chained .timeout() methods is complex.

const superagent = require('superagent'); // Assuming CommonJS for test simplicity

// Example 1: Basic GET
superagent
  .get('/api/users')
  .then(res => {
    console.log(res.body);
  })
  .catch(err => {
    console.error(err);
  });

// Example 2: POST with data
superagent
  .post('/api/submit')
  .send({ name: 'Vibe Check', value: 100 })
  .set('accept', 'json')
  .then(res => console.log('ok'));

// Example 3: Direct call style
superagent('DELETE', '/api/resource/123').then(res => console.log('deleted'));

// Example 4: With a timeout method call (should still be flagged by current basic check)
superagent
  .get('/api/slow-resource')
  .timeout({
    deadline: 10000, // 10 seconds
  })
  .then(res => {
    console.log(res.body);
  });

// Example 5: Call via an alias (Likely *missed* by the current simple AST check)
const myAgent = superagent;
myAgent.put('/api/update/456').send({ status: 'updated' }); 