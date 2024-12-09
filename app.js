// Hardcoded admin credentials
const adminCredentials = {
    username: "admin",
    password: "miamom" // Updated password
};

// Storage for user accounts and data
let userAccounts = {}; // { username: { passwordHash, passwordPlaintext, encryptedData } }
let currentUser = null;

// Hash function
function hashPassword(password) {
    return CryptoJS.MD5(password).toString();
}

// Encryption functions
function encryptData(data, password) {
    return CryptoJS.AES.encrypt(JSON.stringify(data), password).toString();
}

function decryptData(encryptedData, password) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, password);
    return JSON.parse(bytes.toString(CryptoJS.enc.Utf8));
}

// Show the login form
document.getElementById('show-login-btn').addEventListener('click', () => {
    document.getElementById('login-form').style.display = "block";
    document.getElementById('register-form').style.display = "none";
    document.getElementById('auth-message').innerText = "";
});

// Show the register form
document.getElementById('show-register-btn').addEventListener('click', () => {
    document.getElementById('register-form').style.display = "block";
    document.getElementById('login-form').style.display = "none";
    document.getElementById('auth-message').innerText = "";
});

// Admin Login
document.getElementById('login-btn').addEventListener('click', () => {
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;

    if (username === adminCredentials.username && password === adminCredentials.password) {
        // If login is successful, show the admin panel
        document.getElementById('auth-interface').style.display = "none";
        document.getElementById('admin-panel').style.display = "block";
        displayAdminData();
    } else {
        // If login fails, show an error message
        document.getElementById('auth-message').innerText = "Invalid admin credentials.";
    }
});

// Registration
document.getElementById('register-btn').addEventListener('click', () => {
    const username = document.getElementById('register-username').value;
    const password = document.getElementById('register-password').value;

    // Hash the password before storing
    const passwordHash = hashPassword(password);
    const passwordPlaintext = password;

    // Store the user account
    userAccounts[username] = { passwordHash, passwordPlaintext, encryptedData: "" };

    document.getElementById('auth-message').innerText = `User ${username} registered successfully!`;
    document.getElementById('register-username').value = '';
    document.getElementById('register-password').value = '';
});

// Display Admin Panel Data
function displayAdminData() {
    let output = "<h3>User Accounts</h3><table><tr><th>Username</th><th>Password Hash</th><th>Actions</th></tr>";

    for (const username in userAccounts) {
        const user = userAccounts[username];
        output += `<tr>
                        <td>${username}</td>
                        <td>${user.passwordHash}</td>
                        <td><button onclick="editUser('${username}')">Edit</button></td>
                    </tr>`;
    }

    output += "</table>";
    document.getElementById('admin-output').innerHTML = output;
}

// Edit User Data
function editUser(username) {
    const user = userAccounts[username];
    document.getElementById('edit-username').value = username;
    document.getElementById('edit-password').value = "";
    document.getElementById('edit-encryptedData').value = user.encryptedData;

    document.getElementById('admin-edit-form').style.display = "block";

    // Save changes
    document.getElementById('save-edit-btn').onclick = () => {
        const newPassword = document.getElementById('edit-password').value;
        const newEncryptedData = document.getElementById('edit-encryptedData').value;

        if (newPassword) {
            userAccounts[username].passwordHash = hashPassword(newPassword);
            userAccounts[username].passwordPlaintext = newPassword;
        }
        if (newEncryptedData) {
            userAccounts[username].encryptedData = newEncryptedData;
        }

        // Refresh admin data view
        displayAdminData();
        document.getElementById('admin-edit-form').style.display = "none";
    };
}

// Logout as Admin
document.getElementById('logout-admin-btn').addEventListener('click', () => {
    document.getElementById('admin-panel').style.display = "none";
    document.getElementById('auth-interface').style.display = "block";
});
