import 'package:flutter_secure_storage/flutter_secure_storage.dart';

import '../noise/base64url.dart';
import '../noise/dh.dart';

/// 手机静态身份密钥（X25519）。私钥进 Android Keystore / iOS Keychain
/// （flutter_secure_storage 底层），不出设备。对应桌面 `DesktopIdentity`。
class IdentityStore {
  static const _key = 'phone_static_private_v1';
  final FlutterSecureStorage _storage;

  IdentityStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  DhKeyPair? _cached;

  Future<DhKeyPair> loadOrCreate() async {
    if (_cached != null) return _cached!;

    final existing = await _storage.read(key: _key);
    if (existing != null) {
      final priv = Base64Url.decode(existing);
      return _cached = await Dh.fromPrivate(priv);
    }

    final kp = await Dh.generate();
    await _storage.write(key: _key, value: Base64Url.encode(kp.privateKey));
    return _cached = kp;
  }
}
