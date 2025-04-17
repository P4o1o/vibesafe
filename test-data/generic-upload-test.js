// Test file for generic new FormData() pattern

function handleFormSubmit(event) {
    event.preventDefault();
    const formElement = event.target;
    
    // Create a new FormData object
    const formData = new FormData(formElement);

    // Append extra data if needed
    formData.append('user', 'testuser');

    console.log('FormData created:', formData);

    // Example: Send formData using fetch (fetch call itself isn't the focus)
    /*
    fetch('/api/upload', {
        method: 'POST',
        body: formData,
    })
    .then(response => response.json())
    .then(data => console.log('Success:', data))
    .catch((error) => console.error('Error:', error));
    */
}

// Assume there's an HTML form with id="uploadForm"
// const form = document.getElementById('uploadForm');
// form.addEventListener('submit', handleFormSubmit); 