/**
* File:    Bury.js
* Author:  J. Ian Lindsay
* Date:    2015.11.19
*
*        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*                    Version 2, December 2004
*
* Copyright (C) 2015 J. Ian Lindsay <josh.lindsay@gmail.com>
*
* Everyone is permitted to copy and distribute verbatim or modified
* copies of this license document, and changing it is allowed as long
* as the name is changed.
*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
*
*  0. You just DO WHAT THE FUCK YOU WANT TO.
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
*   PAYLOAD_SIZE field of the header. The checksum only relates to the MESSAGE DATA, and not to the HEADER.
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
*  When the decrypting party successfully decodes the message, they can set $write_file = $path-to-dir, and the file will be
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
var fs         = require('fs');           // File i/o
var gd         = require('node-gd');      // Image manipulation library.
var MCrypt     = require('mcrypt');       // Cryptograhy
var compressjs = require('compressjs');   // Compression library.
var CryptoJS   = require("crypto-js");    // Hash

var bzip2      = compressjs.bzip2;

// These are global constants for the library.
var VERSION_CODE    = 0x01;   // The version of the program. Will be included in the carrier.
var MIN_PASS_LENGTH = 8;      // The length of the smallest password we will tolerate.

var LOG_DEBUG = 7;
var LOG_INFO  = 5;
var LOG_ERR   = 2;


// Instancing this object represents a full operation on a carrier.
function Bury(carrier_path, password, options) {
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

  /* These parameters are derived from the password. Do not set them directly. */
    var __max_stride   = -1;    // How much range should we allow in the arhythmic stride?
    var __offset       = -1;    // The first pixel to mean something.
    var __stride_seed  = -1;    // Use an arythmic stride between relevant pixels.
    var __strides      = [];    // Count off the intervals between pixels.
    var __usablePixels = 0;     // How many pixels are we capable of using?

  // Holds the filename if setMessage() is called with a path.
  var __file_name_info  = false;


  var max_payload_size = -1;  // Used to decide how much plaintext we can stuff into the carrier.
  var payload_size     = -1;  // The size of the message after encryption and compression


  /*
  * These are the options that can be supplied to the bury operation.
  *  The members below represents an exhaustive list, and the default values for each option.
  */
  options = options ? options : {};
    // Enabled carrier channels. No alpha support due to it standing out like a flare that says: 'ANOMALY!'.
    // It should also be noted that not using all of the channels makes the statistical profile of the
    //   noise asymetrical. No human being could ever see this with their eyes, but a machine might.
    var enableRed       = options.hasOwnProperty('enableRed')      ? options.enableRed         : true;
    var enableGreen     = options.hasOwnProperty('enableGreen')    ? options.enableGreen       : true;
    var enableBlue      = options.hasOwnProperty('enableBlue')     ? options.enableBlue        : true;

    // DEBUG OPTION    Set to true to expose the affected pixels in the image.
    var visibleResult   = options.hasOwnProperty('visibleResult')  ? options.visibleResult     : false;

    // DEBUG OPTION    How noisy should this class be about what it's doing?
    var verbosity       = options.hasOwnProperty('verbosity')      ? options.verbosity         : LOG_DEBUG;

  /* These options apply to treatment of filenames for embedded files. */
    // If the user sets this to false, we will not store file information.
    var store_filename  = options.hasOwnProperty('storeFilename')  ? options.storeFilename     : true;

    // Decrypt only: Should we write an output file, if applicable?
    var write_file      = options.hasOwnProperty('writeFile')      ? options.writeFile         : true;

  // Crush the message prior to encrypting?
  var compress        = options.hasOwnProperty('compress')       ? options.compress          : true;

  // Should the output image be scaled to a minimum-size needed to fit the message?
  var rescaleCarrier  = options.hasOwnProperty('rescaleCarrier') ? options.rescaleCarrier    : true;



  /*
  * Alrighty.... Let's setup crypto stuff...
  */
  console.log(MCrypt.getAlgorithmNames());
  console.log(MCrypt.getModeNames());
  var aes_cipher = new MCrypt.MCrypt('rijndael-128', 'cbc');


  /**************************************************************************
  * Everything below this block is internal machinary of the class.         *
  **************************************************************************/

  var log_error = function(body, v) {
    v = v ? v : LOG_DEBUG;
    if (v <= verbosity) console.log(body);
  };


  /**
  * Call to shink the carrier to the minimum size required to store the bitstream.
  *  Maintains aspect ratio.
  *  Checks for adequate size.
  *  Regenerates strides.
  */
  var rescale_carrier = function() {
    var return_value  = false;
    var bits  = __payload_size * 8;
    var ratio  = max(__x, __y) / min(__x, __y);
    var required_pixels  = __offset;
    var bpp = getBitsPerPixel();  // How many bits-per-pixel can we have?
    var n  = 0;
    while ((bits > 0) && (isset(__strides[n]))) {
      required_pixels  += __strides[n++];
      bits  = bits - bpp;
    }
    log_error('Need a total of ' + required_pixels + ' pixels to store the given message with given password.');

    n  = ceil(sqrt(required_pixels / ratio));
    var width  = n;
    var height  = n;
    if (__x >= __y) width = ceil(width * ratio);
    else height = ceil(height * ratio);

    var img  = gd.createTrueColorSync(width, height);
    if (img) {
      if (img.copyResized(__image, 0, 0, 0, 0, width, height, __x, __y)) {
        if ((height * width) < (__x * __y)) {    // Did we actually shrink the carrier?
          if ((height * width) >= required_pixels) {    // Do we have enough space in the new carrier?
            __image.destroy();
            __image  = img;
            __x  = img.width();
            __y  = img.height();
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
  *  Returns a reference to the new truecolor image.
  */
  var upgrade_color = function() {
    var img  = gd.createTrueColorSync(__x, __y);
    __image.copy(img, 0, 0, 0, 0, __x, __y);
    __image.destroy();
    __image.destroy();
    log_error('Resampled image into truecolor.', LOG_WARNING);
    return img;
  }


  /**************************************************************************
  * These functions deal with deriving parameters from the key material.    *
  **************************************************************************/

  var toByteArray = function(word_array) {
    var byte_array = [];
    for (var i = 0; i < word_array.length; i++) {
      byte_array[i*4+0] = 0x000000FF & (word_array[i] >> 24);
      byte_array[i*4+1] = 0x000000FF & (word_array[i] >> 16);
      byte_array[i*4+2] = 0x000000FF & (word_array[i] >> 8);
      byte_array[i*4+3] = 0x000000FF & (word_array[i]);
    }
    return byte_array;
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
  */
  var deriveParamsFromKey = function(pw) {
    var t_initial = (new Date).getTime();

    var hash      = CryptoJS.SHA256(pw);      // Give us back 32 bytes.
    var hash_arr  = toByteArray(hash.words);  // Need to access it byte-wise...
    __offset      = hash_arr[0];              // Where does the first header byte go?

    // How many hash rounds should we run on the password? Limit it to 9000. We don't want to go over 9000.
    var rounds    = ((hash_arr[1] * 256) + hash_arr[2]) % 9000;
    __max_stride  = 2+(hash_arr[3] % 14);  // The maximum stride.

    // Use the remaining bits to seed the RNG for arythmic stride.
    var temp  = [];
    for (var i = 0; i < 7; i++) {
      temp[0]  = hash_arr[(i+4)]  ^ temp[0];
      temp[1]  = hash_arr[(i+11)] ^ temp[1];
      temp[2]  = hash_arr[(i+18)] ^ temp[2];
      temp[3]  = hash_arr[(i+25)] ^ temp[3];
      //$this->log_error(__METHOD__.' RNG ['.($i+4).', '.($i+11).', '.($i+18).', '.($i+25).']');
    }
    // //$this->log_error(__METHOD__.' Seed Prep: '.$temp[0].' '.$temp[1].' '.$temp[2].' '.$temp[3]);
    __stride_seed = (((temp[0] *16777216) % 128) + (temp[1] * 65536) + (temp[2] * 256) + temp[3]);

    // Spin the password around for awhile...
    for (var i = 0; i < rounds; i++) hash  = CryptoJS.SHA256(hash);
    __key  = toByteArray(hash.words);      // Now we have the 256-bit key.
    var t_final = (new Date).getTime();
    var t_delta = t_final - t_initial;
    log_error('Executed '+rounds+' rounds in ' + t_delta + 'ms.', LOG_INFO);
  };


  /**
  * Projective function that will run the arythmic stride as far out as the carrier
  *  will allow, and save the results as an array of integers. The modulator will
  *  need this array later to lay the data down into the proper pixels.
  */
  var demarcate_strides = function() {
    if (__stride_seed >= 0) {
      mt_srand(__stride_seed);
      __usable_pixels  = 0;  // How many pixels can we use?
      var total_remaining  = (__x * __y) - __offset;  // Total remaining pixels.
      while (total_remaining > 0) {
        var delta  = mt_rand(1, __max_stride);
        total_remaining  = total_remaining - delta;
        if ($total_remaining > 0) {
          __usable_pixels++;
          __strides.push(delta);
        }
      }
      log_error('There are ' + __usable_pixels + ' usable pixels.', LOG_INFO);
      findMaxPayloadSize();
    }
    else {
      log_error("Somehow there is no seed value.", LOG_WARNING);
    }
  };


  /*
  *  Given the stride info, figure out how much data we can pack into the carrier.
  *  Returns an integer.
  */
  var findMaxPayloadSize = function() {
    var bpp = getBitsPerPixel();
    var raw_pixels  = (__x * __y) - __offset;
    var stride_pix  = __strides.length;
    __max_payload_size = floor((bpp * stride_pix) / 8);    // The gross size.
    log_error('Maximum message size is ' + __max_payload_size + ' bytes.', LOG_INFO);
    return __max_payload_size;
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
    var i  = floor(__offset / __x);
    var temp  = __image.colorAt(j, i);

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
      if (strlen(__file_name_info) != 32) {
        log_error('Filename was not 32 bytes. storing it generically...', LOG_WARNING);
        __file_name_info  = '                bad_filename.txt';
      }
      __plaintext  = __file_name_info + __plaintext;
    }

    var nu_iv      = generateIv();
    __iv_size = 128;  // TODO: ????

    var compressed = (compress) ? bzip2.compressFile(__plaintext, 9) : __plaintext;
    //var encrypted  = nu_iv+ mcrypt_encrypt(CIPHER, $this->key, $compressed, BLOCK_MODE, $nu_iv);
    //
    var checksum  = CryptoJS.MD5(encrypted);
    console.log(JSON.stringify(checksum, null, 4));
    // $message_params  = $message_params | ((compress)      ? 0x01:0x00);
    // $message_params  = $message_params | (($this->store_filename)  ? 0x04:0x00);
    // log_error('MESSAGE_PARAMS: 0x'.sprintf('%02X', $message_params).'.', LOG_INFO);
    //
    // $this->ciphertext  = pack('vxCxN', VERSION_CODE, $message_params, strlen($encrypted.$checksum)).$encrypted.$checksum;
    //
    // __payload_size  = strlen($this->ciphertext);  // Record the number of bytes to modulate.
    //
    // if (compress) {
    //   $pt_len    = strlen($this->plaintext);
    //   $comp_len  = strlen($compressed);
    //   log_error('Compressed '.$pt_len.' bytes into '.$comp_len.'.', LOG_INFO);
    // }
    // if ($this->store_filename) {
    //   log_error('Prepended filename to plaintext: '.__file_name_info, LOG_INFO);
    // }
    return return_value;
  }


  /*
  *  Embed the header and ciphertext into the carrier.
  */
  var modulate = function() {
    set_channel_spec();    // Record the channels in use.
    __bit_cursor  = 0;
    var initial  = __offset + __strides[0];  // The offset stores the active channel settings.

    log_error('Initial pixel of modulation: (' + get_x_coords_by_linear(initial) + ', ' + get_y_coords_by_linear(initial) + ') (x, y).');

    // Visit each usable pixel and modulate it.
    var abs_pix  = __offset;
    for (var n = 0; n < __strides.length; n++) {
      var abs_pix  = abs_pix + __strides[n];
      var i  = get_x_coords_by_linear(abs_pix);
      var j  = get_y_coords_by_linear(abs_pix);

      var temp  = __image.colorAt(i, j);

      var red    = (temp >> 16) & 0xFF;
      var green  = (temp >> 8) & 0xFF;
      var blue   = (temp) & 0xFF;

      var bit;

      if (visible_result) {
         if (enableRed)    bit = getBit();
         if (enableBlue)   bit = getBit();
         if (enableGreen)  bit = getBit();

         if (bit === false) {
           red = 0x00;
           blue = 0x00;
           green  = 0xff;
         }
         else {
           green = 0x00;
           blue = 0x00;
           red  = 0xff;
         }
       }
      else {
        if (enableRed) {
          bit    = getBit();
          if (bit !== FALSE) red  = (red & 0xFE) + bit;
        }

        if (enableBlue) {
          bit    = getBit();
          if (bit !== FALSE) blue  = (blue & 0xFE) + bit;
        }

        if (enableGreen) {
          bit    = getBit();
          if (bit !== FALSE) green  = (green & 0xFE) + bit;
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
    if (__bit_cursor < (__payload_size * 8)) {
      var byte  = floor(__bit_cursor / 8);
      var bit   = __bit_cursor % 8;
      var mask  = 0x01 << bit;
      var feed  = __ciphertext[byte];
      return_value  = (feed & mask) ? 0x01:0x00;
      __bit_cursor++;
    }
    else {
      return_value  = (visible_result) ? false: (rand(0,1))  ? 0x01:0x00;
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
  var get_y_coords_by_linear = function(linear) { return floor($linear / __x); }


  /**************************************************************************
  * Functions related to getting the message out of the image.              *
  **************************************************************************/
  /**
  * Before we can read the header, we need to know which channels it is spread
  *  across.
  */
  var get_channel_spec = function() {
    var temp    = __image.colorAt(
      __offset % __x,
      floor(__offset / __x))
    ;
    enableRed   = ((temp >> 16) & 0x01) ? true : false;
    enableGreen = ((temp >> 8) & 0x01)  ? true : false;
    enableBlue  = (temp & 0x01)         ? true : false;
  }


  /*
  *  Decrypt the ciphertext.
  */
  var decrypt = function() {
    // $return_value  = true;
    // $this->iv_size  = mcrypt_get_iv_size(CIPHER, BLOCK_MODE);    // We need the size of the IV...
    // $nu_iv  = substr($this->ciphertext, 0, $this->iv_size);
    //
    // $ct     = substr($this->ciphertext, $this->iv_size, __payload_size-$this->iv_size);
    // $decrypted    = mcrypt_decrypt(CIPHER, $this->key, $ct, BLOCK_MODE, $nu_iv);
    // $decompressed  = (compress) ? bzdecompress($decrypted) : $decrypted;
    // __file_name_info  = trim(($this->store_filename) ? substr($decompressed, 0, 32) : '');
    // $this->plaintext  = trim(($this->store_filename) ? substr($decompressed, 32) : $decompressed);
    //
    // if (compress) log_error('Compression inflated '.strlen($decrypted).' bytes into '.strlen($decompressed).' bytes.', LOG_INFO);
    // if ($this->store_filename) log_error('Retrieved file name: '.__file_name_info, LOG_INFO);
    // return $return_value;
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
    for (n = 0; n < count(__strides); n++) {
      abs_pix  = abs_pix + __strides[n];
      i  = get_x_coords_by_linear(abs_pix);
      j  = get_y_coords_by_linear(abs_pix);

      temp  = imagecolorat(__image, i, j);

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
    if (decodeHeader(implode(array_map("chr", all_bytes)))) {
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
    //var ver  = unpack('v', substr($bytes, 0, 2));
    // $msg_params  = unpack('C', substr($bytes, 3, 1));
    // $length  = unpack('N', substr($bytes, 5));
    // __payload_size  = $length[1];
    // compress      = (ord($msg_params[1]) & 0x01) ? true : false;
    // $this->store_filename  = (ord($msg_params[1]) & 0x04) ? true : false;
    __ciphertext  = bytes.substr(HEADER_LENGTH);
    // if (VERSION_CODE == $ver[1]) {
    //   log_error('Found a payload length of '.__payload_size.' bytes.');
    //   return true;
    // }
    // else {
    //   log_error('Version code mismatch. File was written by version '.$ver[1].' and this is version '.VERSION_CODE.'.', LOG_ERR);
    //   return false;
    // }
  }

  /*
  * Thanks, Eli...
  * http://stackoverflow.com/questions/2128157/javascript-equivalent-to-c-strncmp-compare-string-for-length
  */
  function strncmp(a, b, n){
    return a.substring(0, n) == b.substring(0, n);
  }

  /**
  * The last 16 bytes of the ciphertext will be a checksum for the encrypted message.
  *  The header has already been removed from the cipher text, so no need to tip-toe around it.
  *  Returns true if the message checks ok.
  *  False otherwise.
  */
  var verify_checksum = function() {
    var msg     = __ciphertext.substr(0, __payload_size-16);
    var chksum  = __ciphertext.substr(__payload_size-16);
    var hash    = CipherJS.MD5(msg);
    __ciphertext  = msg;
    return (!strncmp(chksum, hash, 16));
  }

  /**
  * Set the active channels. Passed no parameters, all channels will be used.
  *  This must be done before the image is set.
  *  At least one channel must be enabled.
  *  Returns false if the current settings are invalid.
  */
  this.setChannels = function(red, green, blue) {
    enableRed   = red   || false;
    enableGreen = green || false;
    enableBlue  = blue  || false;
    findMaxPayloadSize();
    var bpp  = getBitsPerPixel();
    if (bpp === 0) return false;
    var enabled_channels  = enableRed   ? 'Red '   : '';
    enabled_channels     += enableGreen ? 'Green ' : '';
    enabled_channels     += enableBlue  ? 'Blue '  : '';
    log_error('Enabled channels: ' + enabled_channels);
    return true;
  }



  /**
  * Setting the message.
  */
  this.setMessage = function(message, name_override) {
    // $return_value  = false;
    // if (isset($message)) {
    //   if (strlen($this->plaintext) == 0) {
    //     if (is_file($message)) {
    //       log_error('Message looks like a path to a file.', LOG_INFO);
    //       if (is_readable($message)) {
    //         $this->plaintext  = file_get_contents($message);
    //         if ($this->store_filename) {
    //           if ($name_override) $message  = $name_override;    // Facilitates HTML forms.
    //
    //           $base  = basename($message);
    //           __file_name_info  = $this->normalize_filename($base);
    //           log_error('Will use filename: '.__file_name_info, LOG_INFO);
    //         }
    //         log_error('Loaded '.strlen($this->plaintext).' raw message bytes from file.', LOG_INFO);
    //       }
    //       else log_error('Provided message file is not readable.', LOG_INFO);
    //     }
    //     else if (strlen($message) > 0) {
    //       log_error('Message looks like a string.', LOG_INFO);
    //       $this->plaintext  = $message;
    //       $this->store_filename  = false;    // No need for this.
    //     }
    //     else log_error('Message must be either a path or a string.', LOG_ERR);
    //   }
    //   else log_error('Plaintext has already been set.', LOG_ERR);
    // }
    // else log_error('Message length is zero.', LOG_ERR);
    //
    // // If we loaded a message successfully, try to encrypt it and fit it into the carrier.
    // if (strlen($this->plaintext) > 0) {
    //   $this->iv_size  = mcrypt_get_iv_size(CIPHER, BLOCK_MODE);    // We need the size of the IV...
    //   if ($this->iv_size !== false) {
    //     if ($this->encrypt()) {
    //       if (__payload_size <= $this->max_payload_size) {
    //         // Only scale the image down. Never up. To do otherwise exposes the message.
    //         if ($this->rescale) $this->rescale_carrier();
    //
    //         if ($this->modulate()) {
    //           $return_value  = true;
    //         }
    //         else log_error('Modulation failed.', LOG_ERR);
    //       }
    //       else log_error('Encryption produced a payload of '.__payload_size.' bytes, which is '.(__payload_size - $this->max_payload_size).' bytes too large.', LOG_ERR);
    //     }
    //     else log_error('Encryption failed.', LOG_ERR);
    //   }
    //   else log_error('Bad cipher/mode combination.', LOG_ERR);
    // }
    // return $return_value;
  }


  /**
  * Returns a string of length zero. Always.
  */
  var normalize_filename = function($base) {
    // if (($base_len = strlen($base)) == 0) {
    //   return '     ThisFileExtensionWasBad.txt';
    // }
    // $base  = (strlen($base) > 32) ? substr($base, strlen($base)-32):sprintf("%' 32s", $base);
    // return $base;
  }


  /**
  * Tries to retreive a message from the carrier and the given password.
  */
  this.getMessage = function() {
    // $return_value  = false;
    // if (__image) {
    //   if ($this->demodulate()) {
    //     if ($this->decrypt()) {
    //       if ($this->store_filename) {
    //         if ($this->write_file) {
    //           $bytes_out  = file_put_contents($this->write_file+'/'+__file_name_info, $this->plaintext);
    //           if ($bytes_out) {
                 log_error('Wrote '+$bytes_out+' bytes to '+__file_name_info, LOG_INFO);
    //           }
    //           else log_error('Failed to write to file: '+__file_name_info, LOG_WARNING);
    //         }
    //       }
    //       $return_value  = $this->plaintext;
    //     }
    //     else log_error('Decryption failed.', LOG_ERR);
    //   }
    //   else log_error('Demodulation failed.', LOG_ERR);
    // }
    // else log_error('No carrier loaded.', LOG_ERR);
    // return $return_value;
  }


  /**
  *  Dumps the image to a browser (no parameter given), or a file (if a path was provided.
  */
  this.outputImage = function(output_path) {
    if (output_path) {
      __image.savePNG(output_path, function(err) {
          if (err) {
            log_error('Failed to save PNG file.', LOG_ERR);
          }
      });
    }
    else {
      header ('Content-Type: image/png');
      header("Content-Disposition:inline ; filename=output.png");
      imagepng(__image);
    }
  }


  /**
  * Return the filename.
  */
  this.filename = function() {
    //return __file_name_info;
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
    deriveParamsFromKey(password);
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
          return false;
      }
      if (__image) {
        __x  = __image.width;
        __y  = __image.height;
        if (!__image.trueColor) __image = upgrade_color();
        log_error('Loaded carrier with size ('+__x+', '+__y+').');
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
}



///**
//* Report our version.
//*/
//public static function getVersion() {
//  return '0x'.sprintf("%02X", VERSION_CODE);
//}
///**
//* Takes two (or three) passwords and tests them for mutual compatibility. This is needed only in cases
//*  where you want to overlay more than one message (up to three, total) in the same carrier.
//*  Returns true if the passwords are compatible. False otherwise.
//*
//* Compatibility is defined as the condition where no password results in an offset or a stride that overwrites
//*  the first byte of a header from any other password.
//*/
//public static function testPasswordCompatibility($pass0, $pass1, $pass2 = false) {
//  $return_value  = false;
//  $hash0  = hash('sha256', $pass0, true);
//  $hash1  = hash('sha256', $pass1, true);
//  $hash2  = hash('sha256', $pass2, true);
//  $hash_arr0  = str_split($hash0, 1);
//  $hash_arr1  = str_split($hash1, 1);
//  $hash_arr2  = str_split($hash2, 1);
//  $offset0  = ord($hash_arr0[0]);
//  $offset1  = ord($hash_arr1[0]);
//  $offset2  = ord($hash_arr2[0]);
//  $max_stride0  = 2+((ord($hash0[3]) & 0xFF) % 14);
//  $max_stride1  = 2+((ord($hash1[3]) & 0xFF) % 14);
//  $max_stride2  = 2+((ord($hash2[3]) & 0xFF) % 14);
//  // Use the remaining bits to seed the RNG for arythmic stride.
//  $temp  = array(0,0,0,0);
//  for ($i = 0; $i < 7; $i++) {
//    $temp[0]  = ord($hash0[($i+4)]) ^ $temp[0];
//    $temp[1]  = ord($hash0[($i+11)]) ^ $temp[1];
//    $temp[2]  = ord($hash0[($i+18)]) ^ $temp[2];
//    $temp[3]  = ord($hash0[($i+25)]) ^ $temp[3];
//  }
//  $stride_seed0 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);
//  $temp  = array(0,0,0,0);
//  for ($i = 0; $i < 7; $i++) {
//    $temp[0]  = ord($hash1[($i+4)]) ^ $temp[0];
//    $temp[1]  = ord($hash1[($i+11)]) ^ $temp[1];
//    $temp[2]  = ord($hash1[($i+18)]) ^ $temp[2];
//    $temp[3]  = ord($hash1[($i+25)]) ^ $temp[3];
//  }
//  $stride_seed1 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);
//  $temp  = array(0,0,0,0);
//  for ($i = 0; $i < 7; $i++) {
//    $temp[0]  = ord($hash2[($i+4)]) ^ $temp[0];
//    $temp[1]  = ord($hash2[($i+11)]) ^ $temp[1];
//    $temp[2]  = ord($hash2[($i+18)]) ^ $temp[2];
//    $temp[3]  = ord($hash2[($i+25)]) ^ $temp[3];
//  }
//  $stride_seed2 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);
//  $strides0  = array();
//  $strides1  = array();
//  $strides2  = array();
//  $test_limit  = ($pass2) ? max($offset0, $offset1, $offset2) : max($offset0, $offset1);
//  mt_srand($stride_seed0);
//  $i = 0;
//  $n = $offset0;
//  while ($n < $test_limit) {
//    $n  += mt_rand(1, $max_stride0);
//    $strides0[]  = $n;
//  }
//  mt_srand($stride_seed1);
//  $i = 0;
//  $n = $offset1;
//  while ($n < $test_limit) {
//    $n  += mt_rand(1, $max_stride1);
//    $strides1[]  = $n;
//  }
//  mt_srand($stride_seed2);
//  $i = 0;
//  $n = $offset2;
//  while ($n < $test_limit) {
//    $n  += mt_rand(1, $max_stride2);
//    $strides2[]  = $n;
//  }
//  if ($pass2) {
//    if (in_array($offset2, $strides1) || in_array($offset2, $strides0)) {
//    }
//    else if (in_array($offset1, $strides2) || in_array($offset1, $strides0)) {
//    }
//    else if (in_array($offset0, $strides1) || in_array($offset0, $strides2)) {
//    }
//    else {
//      $return_value  = true;
//    }
//  }
//  else {
//    if (in_array($offset0, $strides1) || in_array($offset1, $strides0)) {
//    }
//    else {
//      $return_value  = true;
//    }
//  }
//  return $return_value;
//}
//

module.exports = Bury;
