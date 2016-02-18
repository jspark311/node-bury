var Bury = require('./mcrypt-bury.js');

// Decrypting
var test_readback = new Bury('./test_carrier.png', 'saddroPs');
console.log(test_readback.getMessage());
