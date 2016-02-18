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


// Decrypting
var test_readback = new Bury('./test_carrier.png', 'saddroPs');
console.log(test_readback.getMessage());
