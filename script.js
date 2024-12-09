// Storage for user accounts and data
let userAccounts = {}; // { username: { passwordHash, passwordPlaintext, encryptedData } }
let currentUser = null;

// Hardcoded admin credentials
const adminCredentials = {
    username: "admin",
    password: "miamom" // Updated password
};

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

// Registration
document.getElementById('register-btn').addEventListener('click', () => {
    const username = document.getElementById('username').value;
    const password = document.getElementById('auth-password').value;

    if (!username || !password) {
        document.getElementById('auth-message').innerText = "Please enter a username and password.";
        return;
    }

    if (userAccounts[username]) {
        document.getElementById('auth-message').innerText = "Username already exists.";
        return;
    }

    // Store both the hashed password and the plaintext password
    userAccounts[username] = {
        passwordHash: hashPassword(password),
        passwordPlaintext: password,  // Store plaintext password for educational purposes
        encryptedData: null
    };
    document.getElementById('auth-message').innerText = "Registration successful! Please log in.";
});

// Admin Panel - Display All User Accounts
function displayAdminData() {
    let adminDataHtml = "<h3>User Accounts</h3>";
    adminDataHtml += `<table border="1">
                        <tr>
                            <th>Username</th>
                            <th>Password Hash</th>
                            <th>Password (Plaintext)</th>
                            <th>Encrypted Data</th>
                            <th>Actions</th>
                        </tr>`;

    Object.keys(userAccounts).forEach((username) => {
        const user = userAccounts[username];
        adminDataHtml += `<tr>
                            <td>${username}</td>
                            <td>${user.passwordHash}</td>
                            <td><span id="plaintext-${username}" style="display:none;">${user.passwordPlaintext}</span></td>
                            <td>${user.encryptedData ? "Data Exists" : "No Data"}</td>
                            <td>
                                <button onclick="togglePasswordView('${username}')">Toggle Password View</button>
                                <button onclick="editUser('${username}')">Edit</button>
                            </td>
                          </tr>`;
    });

    adminDataHtml += "</table>";
    document.getElementById('admin-output').innerHTML = adminDataHtml;
}

// Toggle password view (Hash/Plaintext)
function togglePasswordView(username) {
    const plaintextPassword = document.getElementById(`plaintext-${username}`);
    if (plaintextPassword.style.display === "none") {
        plaintextPassword.style.display = "inline";  // Show plaintext password
    } else {
        plaintextPassword.style.display = "none";  // Hide plaintext password
    }
}

// Admin Edit User Account (Updated to Reset Password)
function editUser(username) {
    const user = userAccounts[username];

    // Show the form to edit the user account
    document.getElementById('edit-username').value = username;
    document.getElementById('edit-password').value = user.passwordHash;
    document.getElementById('edit-encryptedData').value = user.encryptedData || "";

    document.getElementById('admin-edit-form').style.display = "block";

    // Handle Save Edit
    document.getElementById('save-edit-btn').onclick = () => {
        const newUsername = document.getElementById('edit-username').value;
        const newPassword = document.getElementById('edit-password').value;
        const newEncryptedData = document.getElementById('edit-encryptedData').value;

        // Reset the password by hashing the new password
        userAccounts[username] = {
            passwordHash: hashPassword(newPassword), // Hash the new password
            passwordPlaintext: newPassword, // Store plaintext for educational purposes
            encryptedData: newEncryptedData
        };

        // Rebuild the user accounts display
        displayAdminData();
        document.getElementById('admin-edit-form').style.display = "none";
    };
}

// Logout Admin
document.getElementById('logout-admin-btn').addEventListener('click', () => {
    document.getElementById('admin-panel').style.display = "none";
    document.getElementById('auth-interface').style.display = "block";
});
