
var Bury = require('./bury.js');

var options = {
  enableRed:      true,
  enableGreen:    true,
  enableBlue:     true,
  compress:       false,
  visibleResult:  true,
  rescaleCarrier: false,
  storeFilename:  false
};

var test_image = new Bury('./test_carrier.jpg', 'saddroPs', options);

// Encrypting
test_image.setMessage('This is a silly test message that the NSA will spend millions of dollars to unearth.');
test_image.outputImage('./test_carrier.png');


// Decrypting
var test_readback = new Bury('./test_carrier.png', 'saddroPs');
console.log(test_readback.getMessage());
