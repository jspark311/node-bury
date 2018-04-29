var Bury = require('./bury.js');

var options = {
  enableRed:      true,
  enableGreen:    true,
  enableBlue:     true,
  //compress:       false,   TODO: This option is still broken in the JS version...
  visibleResult:  false,
  rescaleCarrier: true
};

var test_image = new Bury('./test_carrier.jpg', 'saddroPs', options);

console.log('This is bury ' + Bury.getVersion());

// Encrypting a text message...
test_image.setMessage('This is the worst green-text on the whole internet.');
test_image.outputImage('./test_output.png');
