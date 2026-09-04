import 'dart:convert';
import 'dart:typed_data';

import 'package:credential_typer/crypto/vault_crypto.dart';
import 'package:credential_typer/noise/base64url.dart';
import 'package:credential_typer/noise/protocol.dart';
import 'package:credential_typer/noise/qr_payload.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('KEK 派生确定：相同密码+盐得相同 KEK，不同盐得不同 KEK', () async {
    const p = KdfParams(memory: 4096, iterations: 1, parallelism: 1); // 测试用轻量参数
    final salt1 = Uint8List.fromList(List<int>.filled(16, 7));
    final salt2 = Uint8List.fromList(List<int>.filled(16, 9));
    final pw = utf8.encode('correct horse battery staple');

    final k1 = await VaultCrypto.deriveKek(pw, salt1, p);
    final k1b = await VaultCrypto.deriveKek(pw, salt1, p);
    final k2 = await VaultCrypto.deriveKek(pw, salt2, p);

    expect(k1.length, 32);
    expect(k1, equals(k1b));
    expect(k1, isNot(equals(k2)));
  });

  test('seal/open 往返一致，错密钥解不开', () async {
    final key = VaultCrypto.randomBytes(32);
    final wrong = VaultCrypto.randomBytes(32);
    final secret = utf8.encode('P@ss中文🔐!#\$');

    final blob = await VaultCrypto.seal(key, secret);
    final out = await VaultCrypto.open(key, blob);
    expect(out, equals(Uint8List.fromList(secret)));

    expect(() => VaultCrypto.open(wrong, blob), throwsA(anything));
  });

  test('AAD 绑定：AAD 不符解不开', () async {
    final key = VaultCrypto.randomBytes(32);
    final blob =
        await VaultCrypto.seal(key, utf8.encode('x'), aad: const [1, 2, 3]);
    expect(
        () => VaultCrypto.open(key, blob, aad: const [9]), throwsA(anything));
    final ok = await VaultCrypto.open(key, blob, aad: const [1, 2, 3]);
    expect(utf8.decode(ok), 'x');
  });

  test('二维码载荷往返', () {
    final qr = QrPayload(
      version: Protocol.version,
      sPub: Base64Url.encode(Uint8List(32)),
      host: const ['192.168.1.20', '10.0.0.5'],
      port: 47820,
      code: Base64Url.encode(Uint8List(16)),
    );
    final text = qr.toQrText();
    final back = QrPayload.fromQrText(text);
    expect(back.version, 1);
    expect(back.host, ['192.168.1.20', '10.0.0.5']);
    expect(back.port, 47820);
    expect(back.sPub, qr.sPub);
    expect(back.code, qr.code);
  });

  test('连接码解析会清理剪贴板空白并校验边界', () {
    final spub = Uint8List.fromList(List<int>.generate(32, (i) => i));
    final code = Uint8List.fromList(List<int>.generate(16, (i) => 255 - i));
    final qr = QrPayload(
      version: Protocol.version,
      sPub: Base64Url.encode(spub),
      host: const ['192.168.1.20'],
      port: 47820,
      code: Base64Url.encode(code),
    ).toQrText();
    final parsed = QrPayload.fromQrText('\ufeff  $qr\n');
    expect(parsed.host, ['192.168.1.20']);
    expect(() => QrPayload.fromQrText('bad'), throwsFormatException);
  });
}
