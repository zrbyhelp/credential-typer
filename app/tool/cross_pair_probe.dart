import 'dart:io';

import 'package:credential_typer/noise/dh.dart';
import 'package:credential_typer/noise/qr_payload.dart';
import 'package:credential_typer/transport/tcp_client.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty) throw ArgumentError('QR text required');
  final qr = QrPayload.fromQrText(args.first);
  final phone = await Dh.generate();
  final session = await TcpClient.pair(phone, qr);
  stdout.writeln('CROSS_PAIR_OK');
  await session.close();
}
