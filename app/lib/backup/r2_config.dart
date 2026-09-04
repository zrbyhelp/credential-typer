import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Cloudflare R2 备份配置。凭证仅存 Android Keystore / iOS Keychain
/// （flutter_secure_storage 底层），不落普通存储、不进日志、不进版本控制。
class R2Config {
  /// S3 兼容端点，形如 https://<accountId>.r2.cloudflarestorage.com
  final String endpoint;
  final String bucket;
  final String accessKeyId;
  final String secretAccessKey;

  const R2Config({
    required this.endpoint,
    required this.bucket,
    required this.accessKeyId,
    required this.secretAccessKey,
  });

  bool get isComplete =>
      endpoint.trim().isNotEmpty &&
      bucket.trim().isNotEmpty &&
      accessKeyId.trim().isNotEmpty &&
      secretAccessKey.isNotEmpty;
}

/// R2 配置的安全读写。
class R2ConfigStore {
  static const _kEndpoint = 'r2.endpoint';
  static const _kBucket = 'r2.bucket';
  static const _kAccessKeyId = 'r2.accessKeyId';
  static const _kSecret = 'r2.secretAccessKey';

  final FlutterSecureStorage _storage;

  R2ConfigStore([FlutterSecureStorage? storage])
      : _storage = storage ??
            const FlutterSecureStorage(
              aOptions: AndroidOptions(encryptedSharedPreferences: true),
            );

  Future<R2Config?> load() async {
    final endpoint = await _storage.read(key: _kEndpoint);
    final bucket = await _storage.read(key: _kBucket);
    final accessKeyId = await _storage.read(key: _kAccessKeyId);
    final secret = await _storage.read(key: _kSecret);
    if (endpoint == null ||
        bucket == null ||
        accessKeyId == null ||
        secret == null) {
      return null;
    }
    final cfg = R2Config(
      endpoint: endpoint,
      bucket: bucket,
      accessKeyId: accessKeyId,
      secretAccessKey: secret,
    );
    return cfg.isComplete ? cfg : null;
  }

  Future<void> save(R2Config cfg) async {
    await _storage.write(key: _kEndpoint, value: cfg.endpoint.trim());
    await _storage.write(key: _kBucket, value: cfg.bucket.trim());
    await _storage.write(key: _kAccessKeyId, value: cfg.accessKeyId.trim());
    await _storage.write(key: _kSecret, value: cfg.secretAccessKey);
  }

  Future<void> clear() async {
    await _storage.delete(key: _kEndpoint);
    await _storage.delete(key: _kBucket);
    await _storage.delete(key: _kAccessKeyId);
    await _storage.delete(key: _kSecret);
  }
}
