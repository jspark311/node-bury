/**
* File:    Bury.js
* Author:  J. Ian Lindsay
* Date:    2015.11.19
*
* Copyright (c) 2015 J. Ian Lindsay
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*
*
*
* Author's BTC address:  17da1aqXEhdqMkbEq66nc2n5DeAnrnNbsK
*
* This library is meant to embed an encrypted message into the noise-floor of a carrier image.
*  The message is first compressed, then encrypted, then treated as a bitstream and modulated into
*  the carrier. The data to be written to the carrier is organized like this....
*
*       +--------+------------------------+----------+
*       | HEADER | MESSAGE DATA           | CHECKSUM |
*       +--------+------------------------+----------+
*         |        |                           |
*         |        |                           +-- MD5, stored as binary (16 bytes). See Note0.
*         |        |
*         |        +-- ( IV + ENCRYPT( COMPRESS([FILENAME] + MESSAGE) ) )
*         |
*         +--ACTIVE CHANNELS: 3-bits    // Which channels are used to encode the data? See Note1.
*            VERSION:         2 bytes   // The version of this program that wrote the image.
*            HEADER LENGTH:   1 byte    // The length of this data structure.
*            MESSAGE PARAMS:  1 byte    // Control bits for how the message is handled. See Note5.
*            CHANNEL PARAMS:  1 byte    // These are reserved for later use, but will deal with carrier pre-processing.
*            PAYLOAD SIZE:    4 bytes   // The size of the payload, including the checksum, but NOT the header.
*
* ============================================================================================================================
* Note0: Regarding the checksum
*  The MD5 checksum is the final 16-bytes of the bitstream. It is stored as binary, and its length is included in the
*   payload_size field of the header. The checksum only relates to the MESSAGE DATA, and not to the HEADER.
* ============================================================================================================================
*
* ============================================================================================================================
* Note1: Regarding the first important pixel
*  The channel-parameters are always stored in the pixel at offset 0 (Note3). That pixel's least-significant bits
*   are taken to mean which channels were used to encode everything else. Suppose the first pixel was (in RGB) #425523...
*   RED CHANNEL ENABLED?      0x42 % 0x01  = 0 = FALSE
*   GREEN CHANNEL ENABLED?    0x55 % 0x01  = 1 = TRUE
*   BLUE CHANNEL ENABLED?      0x23 % 0x01  = 1 = TRUE
*
*  The HEADER_LENGTH parameter does not account for these 3-bits.
*
*  All data (including the rest of the HEADER) will respect the constraint so determined. Typically, you would want to use
*   every availible channel to keep the noise profile consistent and maximize capacity (or minimize carrier size). But a
*   possible reason to use less than the maximum would be to overlay many messages (up to 3) in the same carrier with
*   different passwords.
* ============================================================================================================================
*
*
* ============================================================================================================================
* Note3: Regarding parameters derived from the password
*  The password is the indirect source for offset and stride. The most-significant byte of the password's SHA256 hash is taken
*   to be the offset of the HEADER, The next two bytes are the number of hash rounds on the password. The fourth byte is
*   used to derive the maximum stride size. And the rest of the bytes are XOR'd to create the seed for the RNG.
* ============================================================================================================================
*
*
* ============================================================================================================================
* Note5: Control bits that affect messages
*  The following is a table of bitmasks and how they relate to message options. Bits not defined here ought to be set randomly.
*  0x01:  Compress message prior to encryption.
*  0x02:  Enable encryption. As of version 0x01, this is always enabled, and ignored on read.
*  0x04:  Prepend filename to stream before compression/encryption. See Note6.
* ============================================================================================================================
*
* ============================================================================================================================
* Note6: Storing files
*  If the encrypting party loaded their message from a file, this feature will be enabled unless they specifically disabled
*   it (more about that later). It is possible to determine if the feature is enabled by checking that the appropriate bit
*   is set in the MESSAGE_PARAMS field (Note5).
*
*  If the feature is enabled, the filename that was stored in the carrier will be truncated (or padded) to 32-bytes and
*   prepended to the data before compression (and therefore, before encryption as well). The file extension (if present)
*   will be preserved, regardless of padding and truncation of the rest of the filename.
*
*  When the decrypting party successfully decodes the message, they can set write_file = path-to-dir, and the file will be
*   re-consituted on their filesystem. This is DANGEROUS on webservers running this code, as an attacker could bypass many
*   security layers related to file uploads. Then again... you can also leverage it to your advantage (putting back-doors
*   for arbitrary script into your systems).
* ============================================================================================================================
*
*
* ============================================================================================================================
* Note7: Compression choices
*  Compression and encryption go together _really_ well for reasons I won't delve into here.
*   The way I saw it, there was no reason to support multiple compression algos. If the user wants to compress, there is no
*   reason to pussyfoot around. Go for density, since it carries the most extreme entropic benefit.
*   Speed? We aren't stremaing data. Be patient. The compression algo must be binary-safe.
*   I chose BZip2.
* ============================================================================================================================
*/
'use strict'
var util       = require('util');         // TODO: Remove when done debugging.
var fs         = require('fs');           // File i/o
var gd         = require('node-gd');      // Image manipulation library.
var binbuf     = require('bufferpack');   // Bleh... typelessness....
var compressjs = require('compressjs');   // Compression library.
var CryptoJS   = require("crypto-js");    // Hash
var rng        = require('mersenne');     // We can't seed Math.random().

var bzip2      = compressjs.Bzip2;

// These are global constants for the library.
var VERSION_CODE    = 0x02;   // The version of the program. Will be included in the carrier.
var MIN_PASS_LENGTH = 8;      // The length of the smallest password we will tolerate.
var HEADER_LENGTH   = 9;      // Length of the header (in bytes).

var LOG_DEBUG = 7;
var LOG_INFO  = 5;
var LOG_ERR   = 2;

var STR_PAD_LEFT  = 1;
var STR_PAD_RIGHT = 2;
var STR_PAD_BOTH  = 3;


/*
*  Thanks, David (from StackOverflow)
*  http://stackoverflow.com/users/60682/david
*  Modified somewhat. Original was...
*
*  Javascript string pad
*  http://www.webtoolkit.info/
*/
var pad = function(str, len, pad, dir) {
  if (typeof(len) == "undefined") { var len = 32;  }
  if (typeof(pad) == "undefined") { var pad = ' '; }
  if (typeof(dir) == "undefined") { var dir = STR_PAD_LEFT; }
  if (len + 1 >= str.length) {
    switch (dir){
      case STR_PAD_LEFT:
        str = Array(len + 1 - str.length).join(pad) + str;
        break;
      case STR_PAD_BOTH:
        var right = Math.ceil((padlen = len - str.length) / 2);
        var left = padlen - right;
        str = Array(left+1).join(pad) + str + Array(right+1).join(pad);
        break;
      default:
        str = str + Array(len + 1 - str.length).join(pad);
        break;
    }
  }
  return str;
};

/**
 * The hash and crypto deal with word arrays. But for sanity's sake, we sometimes
 *   need to access them byte-wise.
 * Assumes big-endian.
 * @return an array of bytes.
 */
var toByteArray = function(word_array) {
  var byte_array = [];
  for (var i = 0; i < word_array.length; i++) {
    byte_array[i*4+0] = 0x000000FF & (word_array[i] >> 24);
    byte_array[i*4+1] = 0x000000FF & (word_array[i] >> 16);
    byte_array[i*4+2] = 0x000000FF & (word_array[i] >> 8);
    byte_array[i*4+3] = 0x000000FF & (word_array[i]);
  }
  return byte_array;
};

/* Assumes big-endian. */
var toWordArray = function(byte_array) {
  var word_array = [];
  var temp_word  = 0;
  var w          = 0;
  for (var i = 0; i < byte_array.length; i++) {
    temp_word += byte_array[i] << ((3-(i%4))*8);
    if (3 == i%4) {
      // This is the end of a word.
      word_array[w++] = temp_word;
      temp_word       = 0;
    }
  }
  return word_array;
};

/*
* Thanks, Eli...
* http://stackoverflow.com/questions/2128157/javascript-equivalent-to-c-strncmp-compare-string-for-length
*/
var strncmp = function(a, b, n){
  return a.substring(0, n) == b.substring(0, n);
}


/*
* Taken from:
* http://phpjs.org/functions/basename/
*   discuss at: http://phpjs.org/functions/basename/
*   original by: Kevin van Zonneveld (http://kevin.vanzonneveld.net)
*   improved by: Ash Searle (http://hexmen.com/blog/)
*   improved by: Lincoln Ramsay
*   improved by: djmix
*   improved by: Dmitry Gorelenkov
*/
function basename(path, suffix) {
  var b = path;
  var lastChar = b.charAt(b.length - 1);

  if (lastChar === '/' || lastChar === '\\') b = b.slice(0, -1);
  b = b.replace(/^.*[\/\\]/g, '');
  if (typeof suffix === 'string' && b.substr(b.length - suffix.length) == suffix) {
    b = b.substr(0, b.length - suffix.length);
  }
  return b;
}


/**
* Returns a string of length 32. Always.
*/
var normalize_filename = function(base_name) {
  var base_len = base_name.length;
  if (base_len == 0) {
    return '     ThisFileExtensionWasBad.txt';
  }
  var base  = (base_len > 32) ? base_name.substr(base_len-32) : pad(base_name);
  return base;
}


/**
* Given the password, derive the following parameters....
*  0) Offset (in pixels)
*  1) Hash round count.
*  2) RNG seed
*  3) Maximum stride range.
*  4) Key material via the number from step 1.
*
* Without knowing the key, it should be made as difficult as possible to
*  mine the resulting image for patterns, and it ought to be as unlikely
*  as possible to guess it on accident.
*
* NOTE: RNG implementation will affect the consistency of this function's output.
*/
var deriveParamsFromKey = function(pw) {
  var params = {};
  var t_initial = (new Date).getTime();

  var hash      = CryptoJS.SHA256(pw);      // Give us back 32 bytes.
  var hash_arr  = toByteArray(hash.words);  // Need to access it byte-wise...
  params.offset = hash_arr[0];              // Where does the first header byte go?
  params.max_stride = 2+(hash_arr[3] % 14); // Make sure max-stride falls between 2 and 16 pixels.
  params.hash       = hash_arr;

  // How many hash rounds should we run on the password? Limit it to 9000.
  // We don't want to go over 9000.
  var rounds        = ((hash_arr[1] * 256) + hash_arr[2]) % 9000;

  // Use the remaining bits to seed the RNG for arythmic stride.
  var mixer_array  = [];
  for (var i = 0; i < 7; i++) {
    mixer_array[0]  = hash_arr[(i+4)]  ^ mixer_array[0];
    mixer_array[1]  = hash_arr[(i+11)] ^ mixer_array[1];
    mixer_array[2]  = hash_arr[(i+18)] ^ mixer_array[2];
    mixer_array[3]  = hash_arr[(i+25)] ^ mixer_array[3];
  }

  // Recombine into a 32-bit integer...
  params.stride_seed = (((mixer_array[0] *16777216) % 128) + (mixer_array[1] * 65536) + (mixer_array[2] * 256) + mixer_array[3]);

  // Spin the password around for awhile...
  for (var i = 0; i < rounds; i++) hash  = CryptoJS.SHA256(hash);

  params.key  = toByteArray(hash.words);      // Now we have the 256-bit key.
  params.ms_required = (new Date).getTime() - t_initial;
  params.rounds      = rounds;
  return params;
};





/**
 * Instancing this object represents a full operation on a carrier. Either encrypting or decyrpting.
 * The carrier_path and password parameters are required for both operations.
 * The options parameter is always optional, and if not supplied, defaults will be used.
 */
function Bury(carrier_path, password, options) {
  /**************************************************************************
  * These are the options that can be supplied to the bury operation.       *
  *   The members below represents an exhaustive list, and the default      *
  *   values for each option.                                               *
  **************************************************************************/
  options = options ? options : {};
    // Enabled carrier channels. No alpha support due to it standing out like a flare that says: 'ANOMALY!'.
    // It should also be noted that not using all of the channels makes the statistical profile of the
    //   noise asymetrical. No human being could ever see this with their eyes, but a machine might.
    var enableRed       = options.hasOwnProperty('enableRed')      ? options.enableRed         : true;
    var enableGreen     = options.hasOwnProperty('enableGreen')    ? options.enableGreen       : true;
    var enableBlue      = options.hasOwnProperty('enableBlue')     ? options.enableBlue        : true;

    // DEBUG OPTION    Set to true to expose the affected pixels in the image.
    var visibleResult   = options.hasOwnProperty('visibleResult')  ? options.visibleResult     : false;

    // Crush the message prior to encrypting?
    var compress        = options.hasOwnProperty('compress')       ? options.compress          : true;

    // Should the output image be scaled to a minimum-size needed to fit the message?
    var rescaleCarrier  = options.hasOwnProperty('rescaleCarrier') ? options.rescaleCarrier    : true;

    // If supplied, this function will be called when there is a result ready.
    var callback        = options.hasOwnProperty('callback')       ? options.callback          : false;

    // DEBUG OPTION    How noisy should this class be about what it's doing?
    var verbosity       = options.hasOwnProperty('verbosity')      ? options.verbosity         : LOG_DEBUG;

  /* These options apply to treatment of filenames for embedded files. */
    // Encrypt only: If the user sets this to false, we will not store file information.
    var store_filename  = options.hasOwnProperty('storeFilename')  ? options.storeFilename     : true;

    // Decrypt only: Should we write an output file, if applicable? Ignored for encryption.
    var write_file      = options.hasOwnProperty('writeFile')      ? options.writeFile         : true;


  /**************************************************************************
  * Everything below this block is internal machinary of the class.         *
  **************************************************************************/

  /* These are instance variables for manipulating the carrier image. */
    var __image        = false; // Our working copy of the carrier.
    var __x            = 0;     // Cursor within the image.
    var __y            = 0;     // Cursor within the image.
    var __bitCursor    = 0;     // Used to keep track of how many bits we've (de)modulated.

  /* Variables for the cryptographic operations. */
    var __iv_size      = -1;    // The size of the cipher's initialization vector.
    var __ciphertext   = '';
    var __plaintext    = '';
    var __key          = '';    // Key material for the cipher algo.
    var __header       = '';    // Prepended to the ciphertext to aid choice about length.
    var __payload_size = -1;    // The size of the message after encryption and compression. Not the header.

  /* These parameters are derived from the password. Do not set them directly. */
    var __max_size     = -1;    // Used to decide how much plaintext we can stuff into the carrier.
    var __max_stride   = -1;    // How much range should we allow in the arhythmic stride?
    var __offset       = -1;    // The first pixel to mean something.
    var __stride_seed  = -1;    // Use an arythmic stride between relevant pixels.
    var __strides      = [];    // Count off the intervals between pixels.
    var __usablePixels = 0;     // How many pixels are we capable of using?

  // Holds the filename if setMessage() is called with a path.
  var __file_name_info  = false;



  /* Logging is done this way to make redicrection of output more convenient. */
  var log_error = function(body, v) {
    v = v ? v : LOG_DEBUG;
    if (v <= verbosity) console.log(body);
  };

  /**
  * Call to shink the carrier to the minimum size required to store the bitstream.
  *  Replaces the carrier image with the rescaled version.
  *  Maintains aspect ratio.
  *  Checks for adequate size.
  *  Regenerates strides.
  *
  * Returns true on success, false on failure.
  */
  var rescale_carrier = function() {
    var return_value  = false;
    var bits  = __payload_size * 8;
    var ratio  = Math.max(__x, __y) / Math.min(__x, __y);
    var required_pixels  = __offset;
    var bpp = getBitsPerPixel();  // How many bits-per-pixel can we have?
    var n  = 0;
    while ((bits > 0) && (__strides[n])) {
      required_pixels  += __strides[n++];
      bits  = bits - bpp;
    }
    log_error('Need a total of ' + required_pixels + ' pixels to store the given message with given password.');
    log_error('Need a total of ' + required_pixels + ' pixels to store the given message with given password.');

    n  = Math.ceil(Math.sqrt(required_pixels / ratio));
    var width  = n;
    var height  = n;
    if (__x >= __y) width = Math.ceil(width * ratio);
    else height = Math.ceil(height * ratio);

    var img  = gd.createTrueColorSync(width, height);
    if (img) {
      if (__image.copyResized(img, 0, 0, 0, 0, width, height, __x, __y)) {
        if ((height * width) < (__x * __y)) {    // Did we actually shrink the carrier?
          if ((height * width) >= required_pixels) {    // Do we have enough space in the new carrier?
            __image.destroy();
            __image  = img;
            __x  = img.width;
            __y  = img.height;
            log_error('Scaled carrier into minimum required size for the given password: (' + __x + ', ' + __y + ').', LOG_INFO);
            __strides  = [];  // We will need to truncate the stride array because our image has shrunk.
            demarcate_strides();
          }
          else log_error('Somehow we scaled the carrier and now it doesn\'t have enough space. Using the original carrier...', LOG_WARNING);
        }
        else log_error('Somehow we scaled the carrier and it got larger. Using the original carrier...', LOG_WARNING);
        return_value  = true;
      }
      else log_error('Failed to scale the carrier.', LOG_ERR);
    }
    else log_error('Failed to create the scaled carrier..', LOG_ERR);
    return return_value;
  }


  /**
  * We need a truecolor image to do our trick. Save the user from vimself if ve submits
  *  an image that isn't up to spec.
  */
  var upgrade_color = function() {
    var img  = gd.createTrueColorSync(__x, __y);
    __image.copy(img, 0, 0, 0, 0, __x, __y);
    __image.destroy();
    __image = img;
    log_error('Resampled image into truecolor.', LOG_WARNING);
  }


  /**************************************************************************
  * These functions deal with deriving parameters from the key material.    *
  **************************************************************************/

  /**
  * Projective function that will run the arythmic stride as far out as the carrier
  *  will allow, and save the results as an array of integers. The modulator will
  *  need this array later to lay the data down into the proper pixels.
  */
  var demarcate_strides = function() {
    if (__stride_seed >= 0) {
      rng.seed(__stride_seed);
      var usable_pixels  = 0;  // How many pixels can we use?
      var total_remaining  = (__x * __y) - __offset;  // Total remaining pixels.
      while (total_remaining > 0) {
        var delta  = rng.rand(__max_stride-1)+1;
        total_remaining  = total_remaining - delta;
        if (total_remaining > 0) {
          usable_pixels++;
          __strides.push(delta);
        }
      }
      log_error('There are ' + usable_pixels + ' usable pixels.', LOG_INFO);
      findMaxPayloadSize();
    }
    else {
      log_error("Somehow there is no seed value.", LOG_WARNING);
    }
  };


  /*
  *  Given the stride info, figure out how much data we can pack into the carrier.
  */
  var findMaxPayloadSize = function() {
    var enabled_channels  = enableRed   ? 'Red '   : '';
    enabled_channels     += enableGreen ? 'Green ' : '';
    enabled_channels     += enableBlue  ? 'Blue '  : '';
    log_error('Enabled channels: ' + enabled_channels);
    var bpp = getBitsPerPixel();
    var raw_pixels  = (__x * __y) - __offset;
    var stride_pix  = __strides.length;
    __max_size = Math.floor((bpp * stride_pix) / 8);    // The gross size.
    log_error('Maximum message size is ' + __max_size + ' bytes.', LOG_INFO);
  }


  /**
  * Returns an integer that indicates how many bits we can fit into each pixel using the current settings.
  */
  var getBitsPerPixel = function() {
    var bpp = (enableRed)   ? 1:0;  // How many bits-per-pixel can we have?
    bpp    += (enableGreen) ? 1:0;
    bpp    += (enableBlue)  ? 1:0;
    return bpp;
  }


  /**************************************************************************
  * Functions related to shoveling the message into the carrier image.      *
  *   Compress, encrypt, measure.                                           *
  *   Decide if we can fit it in the image. If we can, we might try.        *
  *   If we try, we need to write the header.                               *
  *                                                                         *
  *   Optionally rescale the image.                                         *
  **************************************************************************/

  /**
  * We need to record which channels we are going to make use of.
  *  Record those pixels at the offset.
  */
  var set_channel_spec = function() {
    var j  = __offset % __x;
    var i  = Math.floor(__offset / __x);
    var temp  = __image.imageColorAt(j, i);

    var red   = ((temp >> 16) & 0xFE) | (enableRed   ? 0x01:0x00);
    var green = ((temp >> 8) & 0xFE)  | (enableGreen ? 0x01:0x00);
    var blue  = (temp & 0xFE)         | (enableBlue  ? 0x01:0x00);

    __image.setPixel(j, i, __image.colorAllocate(red, green, blue));
    log_error('Wrote ('+red+', '+green+', '+blue+') (R, G, B) to offset ' + __offset + '.');
  }


  /*
  *  Encrypt the plaintext.
  */
  var encrypt = function() {
    var return_value  = true;
    var message_params  = 0x00;

    if (store_filename) {
      if (__file_name_info.length != 32) {
        log_error('Filename was not 32 bytes. storing it generically...', LOG_WARNING);
        __file_name_info  = '                bad_filename.txt';
      }
      __plaintext  = __file_name_info + __plaintext;
    }

    __plaintext = __plaintext.toString('binary');

    var compressed = (compress) ? bzip2.compressBlock(__plaintext, __plaintext.length, 9) : __plaintext;

    var cipherObj  = CryptoJS.AES.encrypt(
      compressed.toString('binary'),
      __key.toString('binary'),
      { mode: CryptoJS.mode.CFB,
        padding: CryptoJS.pad.ZeroPadding
      }
    );

    var nu_iv = toByteArray(cipherObj.iv.words);
    var encrypted = toByteArray(cipherObj.ciphertext.words);

    //console.log(util.inspect(cipherObj.iv.words));
    //console.log(util.inspect(nu_iv));
    //console.log(util.inspect(toWordArray(nu_iv)));

    var checksum  = toByteArray(CryptoJS.MD5(encrypted).words);
    var message_params  = message_params | ((compress)       ? 0x01:0x00);
        message_params  = message_params | ((store_filename) ? 0x04:0x00);

    var payload_length = (encrypted.length + nu_iv.length + checksum.length);
    __ciphertext  = new Buffer(payload_length + HEADER_LENGTH, 'binary');
    //console.log(JSON.stringify(__ciphertext, null, 3));
    if (binbuf.packTo('<HxBx', __ciphertext, 0, [VERSION_CODE, message_params])) {
      if (binbuf.packTo('>I',  __ciphertext, 5, [payload_length])) {
        if (binbuf.packTo(nu_iv.length+'B', __ciphertext, HEADER_LENGTH, nu_iv.toString('binary'))) {
          if (binbuf.packTo(encrypted.length+'B', __ciphertext, (HEADER_LENGTH+nu_iv.length), encrypted)) {
            if (binbuf.packTo(checksum.length+'B', __ciphertext, payload_length-16, checksum)) {
              log_error('Packed payload. Ready for modulation.', LOG_DEBUG);
              __payload_size  = __ciphertext.length;  // Record the number of bytes to modulate.
              if (compress) {
                var pt_len    = __plaintext.length;
                var comp_len  = compressed.length;
                log_error('Compressed '+pt_len+' bytes into '+comp_len+'.', LOG_INFO);
              }
              if (store_filename) {
                log_error('Prepended filename to plaintext: '+__file_name_info, LOG_INFO);
              }
              log_error('Encrypted payload with header is '+__payload_size+' bytes.', LOG_INFO);
              return_value = true;
            }
            else log_error('Failed to pack checksum into payload.', LOG_ERR);
          }
          else log_error('Failed to pack ciphertext into payload.', LOG_ERR);
        }
        else log_error('Failed to pack IV into payload.', LOG_ERR);
      }
      else log_error('Failed to pack length into payload.', LOG_ERR);
    }
    else log_error('Failed to pack header into payload.', LOG_ERR);
    return return_value;
  }


  /*
  *  Embed the header and ciphertext into the carrier.
  */
  var modulate = function() {
    set_channel_spec();    // Record the channels in use.
    __bitCursor  = 0;
    var initial  = __offset + __strides[0];  // The offset stores the active channel settings.

    log_error('Initial pixel of modulation: (' + get_x_coords_by_linear(initial) + ', ' + get_y_coords_by_linear(initial) + ') (x, y).');

    // Visit each usable pixel and modulate it.
    var abs_pix  = __offset;
    for (var n = 0; n < __strides.length; n++) {
      var abs_pix  = abs_pix + __strides[n];
      var i  = get_x_coords_by_linear(abs_pix);
      var j  = get_y_coords_by_linear(abs_pix);

      var temp  = __image.imageColorAt(i, j);

      var red   = (temp >> 16) & 0xFF;
      var green = (temp >> 8) & 0xFF;
      var blue  = (temp) & 0xFF;

      var bit;

      if (visibleResult) {
         if (enableRed)    bit = getBit();
         if (enableBlue)   bit = getBit();
         if (enableGreen)  bit = getBit();

         if (bit === false) {
           red   = 0x00;
           blue  = 0x00;
           green = 0xff;
         }
         else {
           green = 0x00;
           blue  = 0x00;
           red   = 0xff;
         }
       }
      else {
        if (enableRed) {
          bit = getBit();
          if (bit !== false) red  = (red & 0xFE) + bit;
        }

        if (enableBlue) {
          bit = getBit();
          if (bit !== false) blue  = (blue & 0xFE) + bit;
        }

        if (enableGreen) {
          bit = getBit();
          if (bit !== false) green  = (green & 0xFE) + bit;
        }
      }
      __image.setPixel(i, j, __image.colorAllocate(red, green, blue));
    }
    return true;
  }


  /**
  *  Given image coordinates, get the bit to be embedded in that pixel.
  *  Otherwise, returns 0 or 1, as the case may dictate.
  */
  var getBit = function() {
    var return_value  = false;
    if (__bitCursor < (__payload_size * 8)) {
      var byte = Math.floor(__bitCursor / 8);
      var bit  = __bitCursor % 8;
      var mask = 0x01 << bit;
      var feed = __ciphertext[byte];
      return_value  = (feed & mask) ? 0x01:0x00;
      __bitCursor++;
    }
    else {
      return_value  = (visibleResult) ? false: (rng.rand(1))  ? 0x01:0x00;
    }
    return return_value;
  }


  /**
  * Helper function that returns the x-component of an image co-ordinate if
  *  we give it a linear length argument.
  */
  var get_x_coords_by_linear = function(linear) { return linear % __x;         }

  /**
  * Helper function that returns the y-component of an image co-ordinate if
  *  we give it a linear length argument.
  */
  var get_y_coords_by_linear = function(linear) { return Math.floor(linear / __x); }


  /**************************************************************************
  * Functions related to getting the message out of the image.              *
  **************************************************************************/
  /**
  * Before we can read the header, we need to know which channels it is spread
  *  across.
  */
  var get_channel_spec = function() {
    var temp    = __image.imageColorAt(
      __offset % __x,
      Math.floor(__offset / __x)
    );
    enableRed   = ((temp >> 16) & 0x01) ? true : false;
    enableGreen = ((temp >> 8) & 0x01)  ? true : false;
    enableBlue  = (temp & 0x01)         ? true : false;
  }


  /*
  *  Decrypt the ciphertext.
  */
  var decrypt = function() {
    var return_value  = true;
    __iv_size  = 16;           // We need the size of the IV...
    var nu_iv  = __ciphertext.slice(0, __iv_size);

    var ct     = __ciphertext.slice(__iv_size, __iv_size + payload_size + HEADER_LENGTH);
    var decrypted     = CryptoJS.AES.decrypt(
      ct.toString('binary'),
      __key,
      {iv: nu_iv}
    );

    //console.log(util.inspect(decrypted))

    var decompressed  = (compress) ? bzip2.decompressFile(decrypted) : decrypted;
    __file_name_info  = store_filename ? decompressed.slice(0, 32).toString('binary').trim() : '';
    __plaintext       = store_filename ? decompressed.slice(32).toString('binary').trim() : decompressed.toString('binary').trim();

    if (compress) log_error('Compression inflated '+decrypted.length+' bytes into '+decompressed.length+' bytes.', LOG_INFO);
    if (store_filename) log_error('Retrieved file name: '+__file_name_info, LOG_INFO);
    return return_value;
  }


  /*
  *  Extract the header and ciphertext from the carrier.
  */
  var demodulate = function() {
    get_channel_spec();
    var all_bytes  = [0x00];
    var byte  = 0;
    var bit   = 0;

    var initial  = __offset + __strides[0];  // The offset stores the active channel settings.
    log_error('Initial pixel of demodulation: ('+get_x_coords_by_linear(initial)+', '+get_y_coords_by_linear(initial)+') (x, y).');

    // Visit each usable pixel and demodulate it.
    var abs_pix  = __offset;
    for (var n = 0; n < __strides.length; n++) {
      abs_pix  = abs_pix + __strides[n];
      var i  = get_x_coords_by_linear(abs_pix);
      var j  = get_y_coords_by_linear(abs_pix);

      var temp  = __image.imageColorAt(i, j);

      if (enableRed) {
        all_bytes[byte]  = (all_bytes[byte] >> 1) + (((temp >> 16) & 0x01) << 7);
        bit++;
        if (bit % 8 == 0)  all_bytes[++byte] = 0x00;
      }

      if (enableBlue) {
        all_bytes[byte]  = (all_bytes[byte] >> 1) + (((temp) & 0x01) << 7);
        bit++;
        if (bit % 8 == 0) all_bytes[++byte] = 0x00;
      }

      if (enableGreen) {
        all_bytes[byte]  = (all_bytes[byte] >> 1) + (((temp >> 8) & 0x01) << 7);
        bit++;
        if (bit % 8 == 0) all_bytes[++byte] = 0x00;
      }
    }

    // This function call makes a choice about the data we just read,
    //  and unifies the channels into a single coherrant bit-stream, or
    //  it errors.
    if (decodeHeader(all_bytes)) {
      if (verify_checksum()) {
        log_error('Message passed checksum.', LOG_INFO);
        return true;
      }
      else log_error('Message failed checksum.', LOG_ERR);
    }
    else log_error('Failed to decode the header.', LOG_ERR);
    return false;
  }



  var decodeHeader = function(bytes) {
    // First, we need to find the header...
    var ver        = binbuf.unpack('<H', bytes, 0);
    var msg_params = binbuf.unpack('<B', bytes, 3);
    __payload_size = binbuf.unpack('>I', bytes, 5);

    compress        = (msg_params & 0x0001) ? true : false;
    store_filename  = (msg_params & 0x0004) ? true : false;
    __ciphertext  = bytes.slice(HEADER_LENGTH);
    if (VERSION_CODE == ver) {
      log_error('Found a payload length of '+__payload_size+' bytes.');
      return true;
    }
    else {
      log_error('Version code mismatch. File was written by version '+ver+' and this is version '+VERSION_CODE+'.', LOG_ERR);
      return false;
    }
  }

  /**
  * The last 16 bytes of the ciphertext will be a checksum for the encrypted message.
  *  The header has already been removed from the cipher text, so no need to tip-toe around it.
  *  Returns true if the message checks ok.
  *  False otherwise.
  */
  var verify_checksum = function() {
    var msg     = __ciphertext.slice(0, __payload_size-16);
    var chksum  = __ciphertext.slice(__payload_size-16);
    var hash    = CryptoJS.MD5(msg);
    __ciphertext  = msg;
    return (!strncmp(chksum.toString(), hash.toString(), 32));
  }


  /**
  * Setting the message.
  */
  this.setMessage = function(message, name_override) {
    var return_value  = false;
    if (message) {
      if (__plaintext.length == 0) {
        //if (fs.lstatSync(message).isFile()) {
        if (false) {  // TODO: Obviously not fully-ported...
          log_error('Message looks like a path to a file.', LOG_INFO);
    //       if (is_readable(message)) {
            __plaintext  = fs.readFileSync(message);
            if (store_filename) {
              if (name_override) message  = name_override;    // Facilitates HTML forms.

              var base  = basename(message);
              __file_name_info  = normalize_filename(base);
              log_error('Will use filename: '+__file_name_info, LOG_INFO);
            }
            log_error('Loaded '+__plaintext.length+' raw message bytes from file.', LOG_INFO);
    //       }
    //       else log_error('Provided message file is not readable.', LOG_INFO);
        }
        else if (message.length > 0) {
          log_error('Message looks like a string.', LOG_INFO);
          // Must pad the message...
          var padded_len = Math.floor(message.length) + (message.length % 16) ? 16 : 0;
          message = pad(message, padded_len, ' ', STR_PAD_RIGHT).toString('binary');
          __plaintext  = new Buffer(message, 'binary');
          store_filename  = false;    // No need for this.
        }
        else log_error('Message must be either a path or a string.', LOG_ERR);
      }
      else log_error('Plaintext has already been set.', LOG_ERR);
    }
    else log_error('Message length is zero.', LOG_ERR);

    // If we loaded a message successfully, try to encrypt it and fit it into the carrier.
    if (__plaintext.length > 0) {
      __iv_size  = 16;    // We need the size of the IV...
      if (__iv_size) {
        if (encrypt()) {
          if (__payload_size <= __max_size) {
            // Only scale the image down. Never up. To do otherwise exposes the message.
            if (rescaleCarrier) rescale_carrier();
            if (modulate()) {
              return_value  = true;
            }
            else log_error('Modulation failed.', LOG_ERR);
          }
          else log_error('Encryption produced a payload of '+__payload_size+' bytes, which is '+(__payload_size - __max_size)+' bytes too large.', LOG_ERR);
        }
        else log_error('Encryption failed.', LOG_ERR);
      }
      else log_error('Bad cipher/mode combination.', LOG_ERR);
    }
    return return_value;
  }


  /**
  * Tries to retreive a message from the carrier and the given password.
  */
  this.getMessage = function() {
    var return_value  = false;
    if (__image) {
      if (demodulate()) {
        if (decrypt()) {
          if (store_filename) {
            if (write_file) {
              fs.writeFile(__file_name_info, __plaintext, 'utf8',
                function(err) {
                  if (err) {
                    log_error('Failed to write to file: '+__file_name_info+' because '+err, LOG_WARNING);
                  }
                  else {
                    log_error('Wrote '+__plaintext.length+' bytes to '+__file_name_info, LOG_INFO);
                  }
                }
              );
            }
          }
          return_value  = __plaintext;
        }
        else log_error('Decryption failed.', LOG_ERR);
      }
      else log_error('Demodulation failed.', LOG_ERR);
    }
    else log_error('No carrier loaded.', LOG_ERR);
    return return_value;
  }


  /**
  * Dumps the image as a base64 string (no parameter given), or a file (if a path was provided.
  */
  this.outputImage = function(output_path, callback) {
    if (output_path) {
      __image.savePng(output_path, function(err) {
        if (err) {
          log_error('Failed to save PNG file.', LOG_ERR);
        }
        if (callback) callback(err)
      });
    }
    else {
      return new Buffer(__image.pngPtr(), 'binary').toString('base64');
    }
  }


  /**
  * Return the filename.
  */
  this.filename = function() {
    return __file_name_info;
  }

  /**
  *  Clean up our mess.
  */
  this.destroyImage = function() {
    if (__image) __image.destroy();
    __image = false;
  }


  if (password.length < MIN_PASS_LENGTH) {
    console.log('Password is too short. You must supply a password with at least ' + MIN_PASS_LENGTH + ' characters.');
  }
  else {
    var params = deriveParamsFromKey(password);
    __key         = params.key;
    __stride_seed = params.stride_seed;
    __max_stride  = params.max_stride;
    __offset      = params.offset;
  }

  /**
  * Try to load the carrier file specified by the argument.
  *  Returns true on success and false on failure.
  */
  if (fs.existsSync(carrier_path)) {
    var ptr = carrier_path.lastIndexOf('.');
    if (ptr > 0) {  // Gee... I sure hope we have a file extension...
      switch (carrier_path.substring(ptr).toLowerCase()) {
        case '.bmp':
          __image  = gd.createFromWBMP(carrier_path);
          break;
        case '.gif':
          __image  = gd.createFromGif(carrier_path);
          break;
        case '.png':
          __image  = gd.createFromPng(carrier_path);
          break;
        case '.jpeg':
        case '.jpg':
          __image  = gd.createFromJpeg(carrier_path);
          break;
        default:
          log_error(carrier_path + ' does not have a supported file extention. Failing, because: no carrier.', LOG_ERR);
      }
      if (__image) {
        __x  = __image.width;
        __y  = __image.height;
        log_error('Loaded carrier with size ('+__x+', '+__y+').');
        if (!__image.trueColor) upgrade_color();
        demarcate_strides();
      }
      else {
        log_error('We got to a point where we ought to have an image, and we don\'t.', LOG_ERR);
      }
    }
    else {
     log_error('Cannot determine file extention.', LOG_ERR);
    }
  }
  else {
    log_error('Bad path. Doesn\'t exist, or isn\'t a file.', LOG_ERR);
  }
};


/**
* Report our version.
*/
Bury.getVersion = function() {
  return ('0x'+pad(VERSION_CODE.toString(16), 2, '0'));
};



/**
* Takes two (or three) passwords and tests them for mutual compatibility. This is needed only in cases
*  where you want to overlay more than one message (up to three, total) in the same carrier.
*  Returns true if the passwords are compatible. False otherwise.
*
* Compatibility is defined as the condition where no password results in an offset or a stride that overwrites
*  the first byte of a header from any other password.
*/
Bury.testPasswordCompatibility = function(pass0, pass1, pass2) {
  var return_value  = false;
  var params0   = {};
  var params1   = {};
  var params2   = {};
  var strides0  = [];
  var strides1  = [];
  var strides2  = [];

  params0 = deriveParamsFromKey(pass0);
  console.log('pass0: "' + pass0 + '"');
  console.log(JSON.stringify(params0, null, 2));

  params1 = deriveParamsFromKey(pass1);
  console.log('pass1: "' + pass1 + '"');
  console.log(JSON.stringify(params1, null, 2));

  var test_limit  = Math.max(params0.offset, params1.offset);

  if (pass2) {
    params2 = deriveParamsFromKey(pass2);
    test_limit  = Math.max(test_limit, params2.offset);
    console.log('pass2: "' + pass2 + '"');
    console.log(JSON.stringify(params2, null, 2));
  }

  console.log('The test only needs to find strides up to ' + test_limit + ' bytes.');

  rng.seed(params0.stride_seed);
  var i = 0;
  var n = params0.offset;
  while (n < test_limit) {
    n += rng.rand(params0.max_stride);
    strides0.push(n);
  }

  rng.seed(params1.stride_seed);
  i = 0;
  n = params1.offset;;
  while (n < test_limit) {
    n += rng.rand(params1.max_stride);
    strides1.push(n);
  }

  if (pass2) {
    rng.seed(params2.stride_seed);
    i = 0;
    n = params2.offset;;
    while (n < test_limit) {
      n += rng.rand(params2.max_stride);
      strides2.push(n);
    }

    if ((strides1.indexOf(params2.offset) >= 0) || (strides0.indexOf(params2.offset) >= 0)) {
    }
    else if ((strides2.indexOf(params1.offset) >= 0) || (strides0.indexOf(params1.offset) >= 0)) {
    }
    else if ((strides1.indexOf(params0.offset) >= 0) || (strides2.indexOf(params0.offset) >= 0)) {
    }
    else {
      return_value  = true;
    }
  }
  else {
    if ((strides1.indexOf(params0.offset) >= 0) || (strides0.indexOf(params1.offset) >= 0)) {
    }
    else {
      return_value  = true;
    }
  }
  return return_value;
};

module.exports = Bury;
