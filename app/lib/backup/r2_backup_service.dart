import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import 'r2_config.dart';

/// 把加密的 vault 快照上传到 Cloudflare R2（S3 兼容）。
///
/// 安全：上传的是 `vault.json` 密文（DEK 被主密码派生的 KEK 封装），R2 上无
/// 主密码不可解——**绝不上传明文**。这里只做对象存储的 SigV4 签名与传输，
/// 不接触任何明文密码。
///
/// 采用 path-style（`https://<host>/<bucket>/<key>`）并手写 AWS SigV4，region
/// 固定 `auto`、service `s3`，避免引入重型 AWS SDK 依赖。
class R2BackupService {
  final R2Config config;
  final HttpClient Function() _clientFactory;

  R2BackupService(this.config, {HttpClient Function()? clientFactory})
      : _clientFactory = clientFactory ?? (() => HttpClient());

  /// R2 上保存最新快照的固定对象键（覆盖式，只留一份最新）。
  static const String objectKey = 'credential-typer/vault.ctvault';
  static const String _probeKey = 'credential-typer/.probe';

  static const String _region = 'auto';
  static const String _service = 's3';

  /// 上传最新加密快照（覆盖）。失败抛异常，异常信息不含敏感数据。
  Future<void> upload(Uint8List vaultBytes) async {
    final resp = await _request('PUT', objectKey, vaultBytes);
    if (resp.status < 200 || resp.status >= 300) {
      throw R2Exception('上传失败（HTTP ${resp.status}）');
    }
  }

  /// 从 R2 拉回最新快照；对象不存在返回 null。
  Future<Uint8List?> download() async {
    final resp = await _request('GET', objectKey, const []);
    if (resp.status == 404) return null;
    if (resp.status < 200 || resp.status >= 300) {
      throw R2Exception('下载失败（HTTP ${resp.status}）');
    }
    return resp.body;
  }

  /// 试连：上传一个极小探针对象。成功返回 null，失败返回可展示的错误信息。
  Future<String?> test() async {
    try {
      final resp = await _request('PUT', _probeKey, utf8.encode('ok'));
      if (resp.status < 200 || resp.status >= 300) {
        return 'HTTP ${resp.status}：请检查 bucket / 密钥 / 端点';
      }
      return null;
    } on R2Exception catch (e) {
      return e.message;
    } catch (e) {
      return '连接失败：$e';
    }
  }

  // —— SigV4 签名 + 传输 ——

  Future<_R2Response> _request(
      String method, String key, List<int> body) async {
    final base = config.endpoint.trim().replaceAll(RegExp(r'/+$'), '');
    final uri = Uri.parse('$base/${config.bucket}/$key');
    final host = uri.host;

    final now = DateTime.now().toUtc();
    final dateStamp = '${now.year.toString().padLeft(4, '0')}'
        '${_two(now.month)}${_two(now.day)}';
    final amzDate = '${dateStamp}T${_two(now.hour)}${_two(now.minute)}'
        '${_two(now.second)}Z';

    final payloadHash = await _sha256Hex(body);
    final canonicalUri =
        '/${_amzEncode(config.bucket)}/${_amzEncode(key, encodeSlash: false)}';
    const canonicalQuery = '';
    final canonicalHeaders = 'host:$host\n'
        'x-amz-content-sha256:$payloadHash\n'
        'x-amz-date:$amzDate\n';
    const signedHeaders = 'host;x-amz-content-sha256;x-amz-date';

    final canonicalRequest = '$method\n$canonicalUri\n$canonicalQuery\n'
        '$canonicalHeaders\n$signedHeaders\n$payloadHash';

    final scope = '$dateStamp/$_region/$_service/aws4_request';
    final stringToSign = 'AWS4-HMAC-SHA256\n$amzDate\n$scope\n'
        '${await _sha256Hex(utf8.encode(canonicalRequest))}';

    final signingKey = await _signingKey(dateStamp);
    final signature = _hex(await _hmac(signingKey, stringToSign));

    final authorization = 'AWS4-HMAC-SHA256 '
        'Credential=${config.accessKeyId}/$scope, '
        'SignedHeaders=$signedHeaders, '
        'Signature=$signature';

    final client = _clientFactory();
    try {
      final req = await client.openUrl(method, uri);
      // host 由 HttpClient 依 uri.host 自动设置，与签名一致。
      req.headers.set('x-amz-date', amzDate);
      req.headers.set('x-amz-content-sha256', payloadHash);
      req.headers.set('authorization', authorization);
      if (body.isNotEmpty) req.add(body);
      final resp = await req.close();
      final bytes = await _collect(resp);
      return _R2Response(resp.statusCode, bytes);
    } finally {
      client.close(force: true);
    }
  }

  Future<Uint8List> _collect(HttpClientResponse resp) async {
    final chunks = <int>[];
    await for (final c in resp) {
      chunks.addAll(c);
    }
    return Uint8List.fromList(chunks);
  }

  Future<List<int>> _signingKey(String dateStamp) async {
    final kDate =
        await _hmac(utf8.encode('AWS4${config.secretAccessKey}'), dateStamp);
    final kRegion = await _hmac(kDate, _region);
    final kService = await _hmac(kRegion, _service);
    return _hmac(kService, 'aws4_request');
  }

  Future<List<int>> _hmac(List<int> key, String data) async {
    final mac = await Hmac.sha256()
        .calculateMac(utf8.encode(data), secretKey: SecretKey(key));
    return mac.bytes;
  }

  Future<String> _sha256Hex(List<int> data) async =>
      _hex((await Sha256().hash(data)).bytes);

  static String _hex(List<int> b) =>
      b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

  static String _two(int n) => n.toString().padLeft(2, '0');

  /// RFC 3986 编码（AWS 规范要求）：非保留字符原样，其余百分号编码；
  /// 对象键里的 '/' 在 canonical URI 中保留。
  static String _amzEncode(String s, {bool encodeSlash = true}) {
    const unreserved =
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~';
    final sb = StringBuffer();
    for (final byte in utf8.encode(s)) {
      final ch = String.fromCharCode(byte);
      if (unreserved.contains(ch)) {
        sb.write(ch);
      } else if (ch == '/' && !encodeSlash) {
        sb.write('/');
      } else {
        sb.write('%');
        sb.write(byte.toRadixString(16).toUpperCase().padLeft(2, '0'));
      }
    }
    return sb.toString();
  }
}

class R2Exception implements Exception {
  final String message;
  R2Exception(this.message);
  @override
  String toString() => message;
}

class _R2Response {
  final int status;
  final Uint8List body;
  _R2Response(this.status, this.body);
}
