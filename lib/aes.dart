import 'dart:convert' show base64, utf8;
import 'dart:typed_data';

import 'package:flutter/foundation.dart';
import 'package:webcrypto/webcrypto.dart' as Cryptography;

class AESMode {
  static const BLOCK = "BLOCK";
  static const COUNTER = "COUNTER";
}

class AES {
  static const int KEY_ROUNDS = 65537;
  static const int KEY_SIZE = 256;

  /*
  * @name generateRandomString
  * @description Generates random String of "n" bytes
  * @returns {Base64 String} Object
  */
  static String generateRandomBytes({
    int length = 16,
    bool encode64 = false,
  }) {
    final data = Uint8List(length);
    Cryptography.fillRandomBytes(data);
    return encode64 ? base64.encode(data) : utf8.decode(data);
  }

  /*
  * @name generateSalt
  * @description Generates random Salt
  * @returns {Base64 String} Object
  */
  static String generateSalt() {
    return generateRandomBytes(
      length: 16,
      encode64: true,
    );
  }

  /*
  * @name generateIV
  * @description Generates random IV
  * @returns {Base64 String} Object
  */
  static String generateIV() {
    return generateRandomBytes(
      length: 16,
      encode64: true,
    );
  }

  /*
  * @name generateKey
  * @description Generate Key from a password
  * @param {String} password
  * @param {Base64 String} salt
  * @returns {Buffer} Buffer object
  */
  static Future<String> generateKey(
    String password,
    String salt,
  ) async {
    final algo = await Cryptography.Pbkdf2SecretKey.importRawKey(
      utf8.encode(password),
    );
    final key = await algo.deriveBits(
      256,
      Cryptography.Hash.sha256,
      base64.decode(salt),
      65537,
    );
    return base64.encode(key);
  }

  /*
  * @name encryptString
  * @description Encrypts a string
  * @param {String} password
  * @param {String} key
  * @param {String Base64} salt
  * @param {String Base64} iv
  * @param {String} data
  * @returns {String} Base64 encoded string
  */
  static Future<String> encryptString({
    String password,
    String key,
    @required String salt,
    @required String iv,
    @required String data,
  }) async {
    key = key ?? await generateKey(password, salt);
    final algo = await Cryptography.AesCbcSecretKey.importRawKey(
      base64.decode(key),
    );
    return base64.encode(
      await algo.encryptBytes(
        utf8.encode(data),
        base64.decode(iv),
      ),
    );
  }

  /*
  * @name decryptString
  * @description Decrypts a string
  * @param {String} password
  * @param {String} key
  * @param {String Base64} salt
  * @param {String Base64} iv
  * @param {String Base64} data
  * @returns {String} utf8 encoded string
  */
  static Future<String> decryptString({
    String password,
    String key,
    @required String salt,
    @required String iv,
    @required String data,
  }) async {
    key = key ?? await generateKey(password, salt);
    final aes = await Cryptography.AesCbcSecretKey.importRawKey(
      base64.decode(key),
    );
    return utf8.decode(
      await aes.decryptBytes(
        base64.decode(data),
        base64.decode(iv),
      ),
    );
  }
}
