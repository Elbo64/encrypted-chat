const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware to parse JSON body
app.use(bodyParser.json());

// Example in-memory message store
const messages = [];

// Generate RSA keys (for encryption and decryption)
const generateKeyPair = () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem'
        }
    });
    // Write the keys to files for later use
    fs.writeFileSync('private.pem', privateKey);
    fs.writeFileSync('public.pem', publicKey);
};

// Generate RSA keys at startup
generateKeyPair();

// Function to encrypt a message
const encryptMessage = (message) => {
    // Read the public key
    const publicKey = fs.readFileSync('public.pem', 'utf8');
    const buffer = Buffer.from(message, 'utf8');
    
    // Encrypt the message with RSA
    const encrypted = crypto.publicEncrypt(publicKey, buffer);

    // Generate a random initialization vector (IV) for AES
    const iv = crypto.randomBytes(16); // 16 bytes for AES block size

    // Generate a 32-byte key for AES-256 encryption (256 bits = 32 bytes)
    const key = crypto.randomBytes(32); // 32 bytes for AES-256

    // Create the cipher using AES-256-CBC
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encryptedMessage = cipher.update(encrypted);
    encryptedMessage = Buffer.concat([encryptedMessage, cipher.final()]);

    // Return IV, encrypted message, and the key used for encryption
    return { iv, encryptedMessage, key };
};

// Function to decrypt a message
const decryptMessage = (encryptedMessage, iv, key) => {
    // Create the decipher using AES-256-CBC
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decryptedMessage = decipher.update(encryptedMessage);
    decryptedMessage = Buffer.concat([decryptedMessage, decipher.final()]);

    // Read the private key for RSA decryption
    const privateKey = fs.readFileSync('private.pem', 'utf8');
    // Decrypt the AES-encrypted message with the private RSA key
    const decrypted = crypto.privateDecrypt(privateKey, decryptedMessage);

    return decrypted.toString('utf8');
};

// POST route to send a message (encrypt before storing)
app.post('/send-message', (req, res) => {
    const { message, recipient } = req.body;
    if (!message || !recipient) {
        return res.status(400).send('Message and recipient are required!');
    }

    // Encrypt the message
    const { iv, encryptedMessage, key } = encryptMessage(message);

    // Store the encrypted message along with the AES key and IV
    messages.push({ recipient, encryptedMessage, iv, key });
    res.status(200).send('Message sent!');
});

// GET route to retrieve messages for a specific recipient (decrypt the message)
app.get('/messages/:recipient', (req, res) => {
    const recipient = req.params.recipient;
    const recipientMessages = messages.filter(msg => msg.recipient === recipient);

    // Decrypt each message before sending it back
    const decryptedMessages = recipientMessages.map(msg => ({
        recipient: msg.recipient,
        message: decryptMessage(msg.encryptedMessage, msg.iv, msg.key)
    }));

    res.status(200).json(decryptedMessages);
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});
