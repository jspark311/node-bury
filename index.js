
var Bury = require('./bury.js');

var options = {
  enableRed:      true,
  enableGreen:    true,
  enableBlue:     true,
  compress:       false,
  visibleResult:  false,
  rescaleCarrier: true,
  storeFilename:  false
};

var test_image = new Bury('./test_carrier.jpg', 'saddroPs', options);

test_image.setMessage('This is a silly test message that the NSA will spend millions of dollars to unearth.');
test_image.outputImage('./test_carrier.png');


//var test_readback = new Bury('./test_carrier.png', 'saddroPs');
//console.log(test_readback.getMessage());

console.log('Done.');
