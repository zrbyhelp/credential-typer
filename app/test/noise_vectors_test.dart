import 'dart:convert';
import 'dart:typed_data';

import 'package:credential_typer/noise/dh.dart';
import 'package:credential_typer/noise/handshake_state.dart';
import 'package:flutter_test/flutter_test.dart';

/// 与桌面 `NoiseVectorTests.cs` 完全相同的官方 cacophony 向量。
/// 这些断言在真机 `flutter test` 通过 = Dart 移植与 C# 字节级一致，
/// 即两端 Noise 握手可互通（这是唯一无法在开发机编译验证、必须真机跑的关键点）。
void main() {
  const initStatic = 'e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1';
  const initEph = '893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a';
  const respStatic = '4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893';
  const respEph = 'bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b';
  const payload0 = '4c756477696720766f6e204d69736573'; // "Ludwig von Mises"
  const payload1 = '4d757272617920526f746862617264'; // "Murray Rothbard"
  final prologue = _hex('4a6f686e2047616c74'); // "John Galt"

  test('KK 匹配官方向量', () async {
    final iS = await Dh.fromPrivate(_hex(initStatic));
    final rS = await Dh.fromPrivate(_hex(respStatic));

    final init = await HandshakeState.create(
      pattern: NoisePattern.kk,
      initiator: true,
      prologue: prologue,
      localStatic: iS,
      remoteStatic: rS.publicKey,
    );
    init.fixedEphemeralPrivate = _hex(initEph);
    final resp = await HandshakeState.create(
      pattern: NoisePattern.kk,
      initiator: false,
      prologue: prologue,
      localStatic: rS,
      remoteStatic: iS.publicKey,
    );
    resp.fixedEphemeralPrivate = _hex(respEph);

    final (msg0, _) = await init.writeMessage(_hex(payload0));
    expect(
      _hx(msg0),
      'ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c79440177015efc1fe7a37c629af7120a96274e6ab7afcc9261901d0e09ae32a5bb96',
    );
    final (got0, _) = await resp.readMessage(msg0);
    expect(_hx(got0), payload0);

    final (msg1, respT) = await resp.writeMessage(_hex(payload1));
    expect(
      _hx(msg1),
      '95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843b274d3429adc47ca093ba63ef90f8da89fda108db471dccfa4894aa7b00003',
    );
    final (got1, initT) = await init.readMessage(msg1);
    expect(_hx(got1), payload1);

    expect(_hx(init.handshakeHash),
        '24c6b51ecb76277140ca018b5985bc9f03de321dae2d34dcae433dafef0131d9');
    expect(_hx(init.handshakeHash), _hx(resp.handshakeHash));
    expect(initT, isNotNull);
    expect(respT, isNotNull);
  });

  test('IK 匹配官方向量', () async {
    final iS = await Dh.fromPrivate(_hex(initStatic));
    final rS = await Dh.fromPrivate(_hex(respStatic));

    final init = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: true,
      prologue: prologue,
      localStatic: iS,
      remoteStatic: rS.publicKey,
    );
    init.fixedEphemeralPrivate = _hex(initEph);
    final resp = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: false,
      prologue: prologue,
      localStatic: rS,
      remoteStatic: null,
    );
    resp.fixedEphemeralPrivate = _hex(respEph);

    final (msg0, _) = await init.writeMessage(_hex(payload0));
    expect(
      _hx(msg0),
      'ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944718da798efbcd91528520204f904b9bd6c7413dccdc214d951e15253e39987f18146e8cd0873654207148333479d4d16c289f0294b29960a72f48e0b7bba2e89083169825e59642148d492020664ccf7',
    );
    final (got0, _) = await resp.readMessage(msg0);
    expect(_hx(got0), payload0);

    // 响应方应在握手中学到发起方静态公钥
    expect(_hx(resp.remoteStaticPublic), _hx(iS.publicKey));

    final (msg1, respT) = await resp.writeMessage(_hex(payload1));
    expect(
      _hx(msg1),
      '95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f1448088435361e70b2ed446e6c9ec387d1d6b3b840f194e373979d241b203c4acafccf5',
    );
    final (got1, initT) = await init.readMessage(msg1);
    expect(_hx(got1), payload1);

    expect(_hx(init.handshakeHash),
        '0b0f68fb0c27e03ce9b97565995ed4838cc0581b762ef72b062f6a546419fad7');
    expect(_hx(init.handshakeHash), _hx(resp.handshakeHash));
    expect(initT, isNotNull);
    expect(respT, isNotNull);
  });

  test('派生 transport 双向可用', () async {
    final iS = await Dh.generate();
    final rS = await Dh.generate();

    final init = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: true,
      prologue: prologue,
      localStatic: iS,
      remoteStatic: rS.publicKey,
    );
    final resp = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: false,
      prologue: prologue,
      localStatic: rS,
      remoteStatic: null,
    );

    final (m0, _) = await init.writeMessage(const <int>[]);
    await resp.readMessage(m0);
    final (m1, respT) = await resp.writeMessage(const <int>[]);
    final (_, initT) = await init.readMessage(m1);

    final plain = utf8.encode('中文密码🔐');
    final ct = await initT!.send.encryptWithAd(const [], plain);
    final dec = await respT!.recv.decryptWithAd(const [], ct);
    expect(_hx(Uint8List.fromList(dec)), _hx(Uint8List.fromList(plain)));

    final plain2 = utf8.encode('pong');
    final ct2 = await respT.send.encryptWithAd(const [], plain2);
    final dec2 = await initT.recv.decryptWithAd(const [], ct2);
    expect(_hx(Uint8List.fromList(dec2)), _hx(Uint8List.fromList(plain2)));
  });
}

Uint8List _hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _hx(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
