const API_URL = 'http://localhost:5000/api';

// Function to handle registration
async function registerUser(formData) {
    try {
        const response = await fetch(`${API_URL}/register`, {
            method: 'POST',
            body: formData
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Registration failed');
        }

        return data;
    } catch (error) {
        throw error;
    }
}

// Function to handle login
async function loginUser(credentials) {
    try {
        const response = await fetch(`${API_URL}/auth/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(credentials)
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.message || 'Login failed');
        }

        // Store token in localStorage
        localStorage.setItem('token', data.token);
        return data;
    } catch (error) {
        throw error;
    }
}
