import 'package:cryptest/aes.dart';
import 'package:flutter/material.dart';

void main() async {
  await testAES();
  runApp(MyApp());
}

Future testAES() async {
  final String data = "Hello World!";
  final String password = "password";
  final String salt = AES.generateSalt();
  final String iv = AES.generateIV();

  // Encrypt
  final eData = await AES.encryptString(
    password: password,
    salt: salt,
    iv: iv,
    data: data,
  );
  print(eData);

  // Decrypt
  final dData = await AES.decryptString(
    password: password,
    salt: salt,
    iv: iv,
    data: data,
  );
  print(dData);
}

class MyApp extends StatelessWidget {
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Cryptest',
      theme: ThemeData(
        primarySwatch: Colors.blue,
      ),
      home: Text("Cryptest"),
    );
  }
}
