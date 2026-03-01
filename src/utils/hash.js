const crypto = require('node:crypto');

function getHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

module.exports = { getHash };
