import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:credential_typer/noise/base64url.dart';
import 'package:credential_typer/noise/byte_channel.dart';
import 'package:credential_typer/noise/dh.dart';
import 'package:credential_typer/noise/frame.dart';
import 'package:credential_typer/noise/handshake_state.dart';
import 'package:credential_typer/noise/protocol.dart';
import 'package:credential_typer/noise/qr_payload.dart';
import 'package:credential_typer/transport/tcp_client.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  test('pair retries the next host when the first handshake is closed', () async {
    final listener = await ServerSocket.bind(InternetAddress.anyIPv4, 0);
    final desktop = await Dh.generate();
    final phone = await Dh.generate();
    final code = Protocol.newPairingCode();
    final qr = QrPayload(
      version: Protocol.version,
      sPub: Base64Url.encode(desktop.publicKey),
      // Both loopback aliases reach this listener. The first connection is
      // deliberately closed to emulate a stale/wrong service on one of the
      // addresses embedded in a QR code.
      host: const ['127.0.0.1', '127.0.0.2'],
      port: listener.port,
      code: Base64Url.encode(code),
    );

    var accepted = 0;
    final responderDone = Completer<void>();
    final subscription = listener.listen((socket) {
      accepted++;
      if (accepted == 1) {
        socket.destroy();
        return;
      }
      unawaited(_respondToPair(socket, desktop, code, responderDone));
    });

    try {
      final session = await TcpClient.pair(phone, qr).timeout(
        const Duration(seconds: 5),
      );
      expect(accepted, greaterThanOrEqualTo(2));
      await responderDone.future.timeout(const Duration(seconds: 2));
      await session.close();
    } finally {
      await subscription.cancel();
      await listener.close();
      code.fillRange(0, code.length, 0);
    }
  });
}

Future<void> _respondToPair(
  Socket socket,
  DhKeyPair desktop,
  Uint8List code,
  Completer<void> done,
) async {
  final channel = ByteChannel(
    input: socket,
    sink: socket.add,
    flush: socket.flush,
    close: () async {
      try {
        await socket.close();
      } catch (_) {}
      socket.destroy();
    },
  );

  try {
    final mode = await channel.readExact(1);
    expect(mode[0], Protocol.modePair);
    final state = await HandshakeState.create(
      pattern: NoisePattern.ik,
      initiator: false,
      prologue: Protocol.pairingPrologue(code),
      localStatic: desktop,
    );
    final message = await Frame.read(channel);
    await state.readMessage(message);
    final (reply, _) = await state.writeMessage(const <int>[]);
    await Frame.write(channel, reply);
    if (!done.isCompleted) done.complete();
  } catch (e, st) {
    if (!done.isCompleted) done.completeError(e, st);
  } finally {
    await channel.close();
  }
}
