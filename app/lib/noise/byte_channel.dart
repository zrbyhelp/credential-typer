import 'dart:async';
import 'dart:collection';
import 'dart:typed_data';

/// 把一个「字节流 + 写入口」抽象成可 `readExact(n)` / `write(bytes)` 的通道。
/// 对 dart:io Socket 做精确读缓冲：Socket 的 data 事件按任意块到达，
/// 这里累积到内部缓冲区，满足挂起的 readExact 请求。
class ByteChannel {
  final void Function(List<int> data) _sink;
  final Future<void> Function() _flush;
  final Future<void> Function() _close;

  final Queue<Uint8List> _chunks = Queue<Uint8List>();
  int _available = 0;
  _PendingRead? _pending;
  Object? _error;
  bool _done = false;

  ByteChannel({
    required Stream<Uint8List> input,
    required void Function(List<int> data) sink,
    required Future<void> Function() flush,
    required Future<void> Function() close,
  })  : _sink = sink,
        _flush = flush,
        _close = close {
    input.listen(
      _onData,
      onError: (Object e, StackTrace st) => _fail(e),
      onDone: () {
        _done = true;
        _tryComplete();
      },
      cancelOnError: true,
    );
  }

  void _onData(Uint8List data) {
    if (data.isEmpty) return;
    _chunks.add(data);
    _available += data.length;
    _tryComplete();
  }

  void _fail(Object e) {
    _error = e;
    final p = _pending;
    _pending = null;
    p?.completer.completeError(e);
  }

  void _tryComplete() {
    final p = _pending;
    if (p == null) return;

    if (_error != null) {
      _pending = null;
      p.completer.completeError(_error!);
      return;
    }
    if (_available >= p.n) {
      _pending = null;
      p.completer.complete(_take(p.n));
      return;
    }
    if (_done) {
      _pending = null;
      p.completer.completeError(const _EndOfStream('连接在读满一帧前被对端关闭'));
    }
  }

  Uint8List _take(int n) {
    final out = Uint8List(n);
    int filled = 0;
    while (filled < n) {
      final chunk = _chunks.removeFirst();
      final need = n - filled;
      if (chunk.length <= need) {
        out.setAll(filled, chunk);
        filled += chunk.length;
      } else {
        out.setAll(filled, chunk.sublist(0, need));
        _chunks.addFirst(Uint8List.sublistView(chunk, need));
        filled += need;
      }
    }
    _available -= n;
    return out;
  }

  Future<Uint8List> readExact(int n) {
    if (_pending != null) {
      throw StateError('readExact 不支持并发调用');
    }
    if (_error != null) return Future.error(_error!);
    if (_available >= n) return Future.value(_take(n));
    if (_done) {
      return Future.error(const _EndOfStream('连接已关闭，无法读满'));
    }
    final p = _PendingRead(n);
    _pending = p;
    return p.completer.future;
  }

  Future<void> write(List<int> data) async {
    _sink(data);
    await _flush();
  }

  Future<void> close() => _close();
}

class _PendingRead {
  final int n;
  final Completer<Uint8List> completer = Completer<Uint8List>();
  _PendingRead(this.n);
}

class _EndOfStream implements Exception {
  final String message;
  const _EndOfStream(this.message);
  @override
  String toString() => 'EndOfStream: $message';
}
