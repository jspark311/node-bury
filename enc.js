var Bury = require('./mcrypt-bury.js');

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

// Encrypting
test_image.setMessage('./Rage_face.png');
console.log(test_image.outputImage('./test_carrier.png'));
