var Bury = require('./bury.js');

// Decrypting requires no options aside from the password. Everything else
//   is either derived, or buried in the header.
var test_readback = new Bury('./test_output.png', 'saddroPs');
console.log(test_readback.getMessage());

// Alternatively, you can read the message into a local file
console.log(test_readback.getMessage({write_file: true}));

