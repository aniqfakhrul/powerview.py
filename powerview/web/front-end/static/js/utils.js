function convertFromSid(sidInput) {
    return fetch('/api/convertfrom/sid', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ objectsid: sidInput })
    })
    .then(response => response.json())
    .catch(error => {
        console.error('Error converting SID:', error);
        throw error; // Re-throw to handle in Alpine.js
    });
}

function convertFromUac(uacInput) {
    return fetch('/api/convertfrom/uacvalue', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ value: uacInput })
    })
    .then(response => response.json())
    .catch(error => {
        console.error('Error converting UAC:', error);
        throw error; // Re-throw to handle in Alpine.js
    });
}