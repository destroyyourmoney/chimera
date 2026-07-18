import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

import 'catalog_page.dart' show CatalogServer;

class CatalogSnapshot {
  CatalogSnapshot({required this.servers, required this.fetchedAt});

  factory CatalogSnapshot.fromJson(Map<String, dynamic> json) =>
      CatalogSnapshot(
        servers: (json['servers'] as List<dynamic>? ?? const [])
            .map((e) => CatalogServer.fromJson(e as Map<String, dynamic>))
            .toList(),
        fetchedAt: DateTime.parse(json['fetchedAt'] as String),
      );

  final List<CatalogServer> servers;
  final DateTime fetchedAt;

  Map<String, dynamic> toJson() => {
    'servers': servers.map((s) => s.toJson()).toList(),
    'fetchedAt': fetchedAt.toIso8601String(),
  };
}

class CatalogCacheStore {
  File? _file;

  Future<File> _path() async {
    if (_file != null) return _file!;
    final dir = await getApplicationSupportDirectory();
    _file = File('${dir.path}/chimera_catalog_cache.json');
    return _file!;
  }

  Future<CatalogSnapshot?> load() async {
    final f = await _path();
    if (!await f.exists()) return null;
    try {
      return CatalogSnapshot.fromJson(
        jsonDecode(await f.readAsString()) as Map<String, dynamic>,
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> save(List<CatalogServer> servers) async {
    final f = await _path();
    final snapshot = CatalogSnapshot(
      servers: servers,
      fetchedAt: DateTime.now(),
    );
    await f.writeAsString(jsonEncode(snapshot.toJson()));
  }

  Future<void> clear() async {
    final f = await _path();
    if (await f.exists()) await f.delete();
  }
}

String relativeTime(DateTime since) {
  final d = DateTime.now().difference(since);
  if (d.inSeconds < 45) return 'just now';
  if (d.inMinutes < 60) {
    return '${d.inMinutes} minute${d.inMinutes == 1 ? '' : 's'} ago';
  }
  if (d.inHours < 24) {
    return '${d.inHours} hour${d.inHours == 1 ? '' : 's'} ago';
  }
  return '${d.inDays} day${d.inDays == 1 ? '' : 's'} ago';
}
