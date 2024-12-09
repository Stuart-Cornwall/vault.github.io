// Storage for user accounts and data
let userAccounts = {}; // { username: { passwordHash, encryptedData } }
let currentUser = null;

// Hardcoded admin password (hash of "secureAdminPass123")
const hashedAdminPassword = "e99a18c428cb38d5f260853678922e03";

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

    userAccounts[username] = { passwordHash: hashPassword(password), encryptedData: null };
    document.getElementById('auth-message').innerText = "Registration successful! Please log in.";
});

// Login
document.getElementById('login-btn').addEventListener('click', () => {
    const username = document.getElementById('username').value;
    const password = document.getElementById('auth-password').value;

    if (username === "admin" && hashPassword(password) === hashedAdminPassword) {
        document.getElementById('auth-interface').style.display = "none";
        document.getElementById('admin-panel').style.display = "block";
        displayAdminData();
        return;
    }

    const user = userAccounts[username];
    if (user && user.passwordHash === hashPassword(password)) {
        currentUser = username;
        document.getElementById('auth-interface').style.display = "none";
        document.getElementById('user-interface').style.display = "block";
    } else {
        document.getElementById('auth-message').innerText = "Invalid username or password.";
    }
});

// Encrypt and Save Data
document.getElementById('encrypt-btn').addEventListener('click', () => {
    if (!currentUser) return;

    const data = document.getElementById('data').value;
    const password = document.getElementById('password').value;

    if (!data || !password) {
        document.getElementById('output').innerText = "Please enter data and encryption password.";
        return;
    }

    userAccounts[currentUser].encryptedData = encryptData(data, password);
    document.getElementById('output').innerText = "Data encrypted and saved!";
});

// Decrypt Data
document.getElementById('decrypt-btn').addEventListener('click', () => {
    if (!currentUser) return;

    const password = document.getElementById('password').value;
    const encryptedData = userAccounts[currentUser].encryptedData;

    if (!encryptedData || !password) {
        document.getElementById('output').innerText = "No data found or password missing.";
        return;
    }

    try {
        const decryptedData = decryptData(encryptedData, password);
        document.getElementById('output').innerText = `Decrypted Data: ${decryptedData}`;
    } catch {
        document.getElementById('output').innerText = "Decryption failed. Incorrect password.";
    }
});

// Logout
document.getElementById('logout-btn').addEventListener('click', () => {
    currentUser = null;
    document.getElementById('user-interface').style.display = "none";
    document.getElementById('auth-interface').style.display = "block";
});

// Admin Panel
function displayAdminData() {
    document.getElementById('admin-output').innerText = JSON.stringify(userAccounts, null, 2);
}

document.getElementById('logout-admin-btn').addEventListener('click', () => {
    document.getElementById('admin-panel').style.display = "none";
    document.getElementById('auth-interface').style.display = "block";
});
