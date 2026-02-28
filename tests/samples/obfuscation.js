// Legitimate high entropy string (e.g. a hash or UUID)
const safeHash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0";

// Malicious-looking obfuscated payload
const payload = "SGVsbG8gd29ybGQhIFRoaXMgaXMgYSBiYXNlNjQgaW5kaWNhdG9yIG9mIHNvbWV0aGluZyBzbmlmeS4uLg==";

// Entropy + eval escalates
eval(Buffer.from(payload, 'base64').toString());
