// Function to hash password using Web Crypto API (SHA-256)
async function hashPassword(password) {
    const encoder = new TextEncoder(); // Converts string to Uint8Array
    const data = encoder.encode(password);
    
    // SHA-256 hashing
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    
    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
    
    return hashHex; // Return hashed password
}

// Default Admin Credentials (for testing purposes)
const adminUsername = 'admin';
const adminPassword = 'miamom'; // This will be hashed

// Initialize users in localStorage if empty
if (!localStorage.getItem('users')) {
    const hashedAdminPassword = await hashPassword(adminPassword);
    const adminUser = {
        username: adminUsername,
        hashedPassword: hashedAdminPassword
    };
    localStorage.setItem('users', JSON.stringify([adminUser]));
}

// Handle Registration
document.getElementById('register-btn').addEventListener('click', async () => {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;
    
    if (username && password) {
        // Hash the password before saving
        const hashedPassword = await hashPassword(password);
        
        // Save the username and hashed password to localStorage (for simplicity)
        let users = JSON.parse(localStorage.getItem('users')) || [];
        users.push({ username, hashedPassword });
        localStorage.setItem('users', JSON.stringify(users));
        
        alert('User registered successfully!');
        document.getElementById('register-form').reset();
    } else {
        alert('Please enter both username and password');
    }
});

// Handle Login
document.getElementById('login-btn').addEventListener('click', async () => {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    
    if (username && password) {
        // Hash the entered password
        const hashedPassword = await hashPassword(password);
        
        // Check if user exists and if the hashed password matches
        let users = JSON.parse(localStorage.getItem('users')) || [];
        const user = users.find(user => user.username === username);
        
        // Check for admin credentials
        if (username === adminUsername && hashedPassword === await hashPassword(adminPassword)) {
            alert('Admin login successful!');
            document.getElementById('admin-panel').style.display = 'block';
            document.getElementById('auth-interface').style.display = 'none';
        } else if (user && user.hashedPassword === hashedPassword) {
            alert('Login successful!');
            document.getElementById('admin-panel').style.display = 'block';
            document.getElementById('auth-interface').style.display = 'none';
        } else {
            alert('Invalid username or password');
        }
    } else {
        alert('Please enter both username and password');
    }
});

// Handle Logout
document.getElementById('logout-admin-btn').addEventListener('click', () => {
    document.getElementById('admin-panel').style.display = 'none';
    document.getElementById('auth-interface').style.display = 'block';
});
