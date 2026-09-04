import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:credential_typer/vault/vault_repository.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  late Directory tmp;

  setUp(() async {
    tmp = await Directory.systemTemp.createTemp('ct_vault_test_');
  });

  tearDown(() async {
    if (await tmp.exists()) await tmp.delete(recursive: true);
  });

  test('verifyMasterPassword：对的返回 true、错的返回 false，且不改解锁态', () async {
    final repo = VaultRepository(tmp.path);
    final pw = utf8.encode('correct horse battery staple');
    await repo.create(pw);
    await repo.upsert(
      title: '示例',
      username: 'alice',
      passwordBytes: utf8.encode('s3cr3t!'),
    );
    expect(repo.isUnlocked, isTrue);

    expect(await repo.verifyMasterPassword(utf8.encode('correct horse battery staple')),
        isTrue);
    expect(await repo.verifyMasterPassword(utf8.encode('wrong pw')), isFalse);
    // 校验不改变解锁态
    expect(repo.isUnlocked, isTrue);
  });

  test('exportBytes / importFrom 往返：正确主密码恢复成功、错误主密码不改库', () async {
    final srcDir = tmp.path;
    final repo = VaultRepository(srcDir);
    final pw = utf8.encode('master-1234');
    await repo.create(pw);
    final acc = await repo.upsert(
      title: 'GitHub',
      username: 'octocat',
      website: 'github.com',
      passwordBytes: utf8.encode('hunter2'),
    );
    final backup = await repo.exportBytes();
    expect(backup, isNotEmpty);

    // 新目录导入：错误主密码 → false 且库不被建立/改动
    final dstDir = await Directory.systemTemp.createTemp('ct_vault_dst_');
    try {
      final repo2 = VaultRepository(dstDir.path);
      final wrongOk =
          await repo2.importFrom(backup, utf8.encode('nope-nope'));
      expect(wrongOk, isFalse);
      expect(repo2.isUnlocked, isFalse);

      // 正确主密码 → true，账户恢复
      final ok = await repo2.importFrom(backup, utf8.encode('master-1234'));
      expect(ok, isTrue);
      expect(repo2.isUnlocked, isTrue);
      final restored = repo2.account(acc.id);
      expect(restored, isNotNull);
      expect(restored!.username, 'octocat');
      expect(restored.website, 'github.com');
      final secret = await repo2.secretBytes(acc.id);
      expect(utf8.decode(secret), 'hunter2');
    } finally {
      await dstDir.delete(recursive: true);
    }
  });

  test('损坏备份 importFrom 返回 false', () async {
    final repo = VaultRepository(tmp.path);
    final bad = Uint8List.fromList(utf8.encode('not a vault'));
    expect(await repo.importFrom(bad, utf8.encode('x')), isFalse);
    expect(repo.isUnlocked, isFalse);
  });

  test('onChanged 在每次落盘后被触发', () async {
    final repo = VaultRepository(tmp.path);
    var count = 0;
    repo.onChanged = () => count++;

    await repo.create(utf8.encode('pw')); // _persist 一次
    expect(count, 1);

    await repo.upsert(
      title: 'A',
      username: 'a',
      passwordBytes: utf8.encode('p'),
    ); // 又一次
    expect(count, 2);

    final id = repo.accounts().first.id;
    await repo.delete(id); // 又一次
    expect(count, 3);
  });
}
