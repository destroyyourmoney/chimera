// Saved-servers list screen: add (form or paste), edit, reorder, remove, and
// bulk "Import subscription" (paste multi-line text or pick a .txt file).
// Reordering doubles as "prioritize this server" -- Pool/AutoPool tries
// endpoints in order/by health, so putting a server first in the assembled
// subscription is a legitimate way to express preference without new Go
// plumbing.
import 'dart:convert';
import 'dart:io';

import 'package:file_selector/file_selector.dart';
import 'package:flutter/material.dart';

import 'chimera_bindings.dart';
import 'server_deploy_page.dart';
import 'server_form.dart';
import 'server_ping.dart';
import 'server_users_page.dart';
import 'settings_store.dart';
import 'theme.dart';

class ServersPage extends StatefulWidget {
  const ServersPage({
    super.key,
    required this.servers,
    required this.onChanged,
  });

  /// servers is owned by the caller (HomePage); this screen mutates it
  /// in place and calls [onChanged] after every mutation so the caller can
  /// persist + rebuild the assembled subscription text.
  final List<ServerEntry> servers;
  final Future<void> Function() onChanged;

  @override
  State<ServersPage> createState() => _ServersPageState();
}

class _ServersPageState extends State<ServersPage> {
  final _bindings = ChimeraBindings.open();
  int _nextId = 0;
  Map<String, ServerPingResult> _pingResults = {};
  bool _pinging = false;

  Future<void> _pingServers() async {
    if (widget.servers.isEmpty || _pinging) return;
    setState(() => _pinging = true);
    try {
      final results = await ServerPing.pingAll(widget.servers, _bindings);
      if (mounted) setState(() => _pingResults = results);
    } finally {
      if (mounted) setState(() => _pinging = false);
    }
  }

  String _newId() =>
      'srv-${DateTime.now().microsecondsSinceEpoch}-${_nextId++}';

  Future<void> _addOrEdit({ServerEntry? existing}) async {
    final result = await Navigator.of(context).push<ServerFormResult>(
      MaterialPageRoute(builder: (_) => ServerFormPage(existing: existing)),
    );
    if (result == null) return;
    setState(() {
      if (existing != null) {
        existing.label = result.label;
        existing.link = result.link;
      } else {
        widget.servers.add(
          ServerEntry(id: _newId(), label: result.label, link: result.link),
        );
      }
    });
    await widget.onChanged();
  }

  /// Deploys chimera-protocol onto a bare VPS over SSH (server_deploy_page.dart)
  /// and saves the resulting server -- the entry point for someone who has no
  /// chimera:// link yet because nothing is installed on their server.
  Future<void> _deployNew() async {
    final result = await Navigator.of(context).push<ServerFormResult>(
      MaterialPageRoute(builder: (_) => const ServerDeployPage()),
    );
    if (result == null) return;
    setState(() {
      widget.servers.add(
        ServerEntry(id: _newId(), label: result.label, link: result.link),
      );
    });
    await widget.onChanged();
  }

  void _remove(ServerEntry e) {
    setState(() => widget.servers.remove(e));
    widget.onChanged();
  }

  /// Opens (setting up admin credentials first if needed) the "manage users"
  /// screen for a server you deployed yourself -- see server_users_page.dart.
  /// Any pasted/imported server can be turned into a managed one this way, as
  /// long as its operator also knows the SSH login and the admin token the
  /// server printed once at startup (or set via -admin-token).
  Future<void> _manageUsers(ServerEntry e) async {
    if (!e.hasAdmin) {
      final configured = await _promptAdminSetup(e);
      if (!configured) return;
      await widget.onChanged();
    }
    if (!mounted) return;
    await Navigator.of(
      context,
    ).push(MaterialPageRoute(builder: (_) => ServerUsersPage(server: e)));
  }

  /// One-time bootstrap: collect the SSH login + admin token for a server so
  /// the app can reach its loopback-only users-admin API through an SSH
  /// tunnel (see ssh_admin_tunnel.dart for why it's loopback-only). This is
  /// the same information `chimera server -admin-listen ... -admin-token ...`
  /// printed/took on that server -- nothing new to generate here.
  Future<bool> _promptAdminSetup(ServerEntry e) async {
    final hostCtrl = TextEditingController(text: e.adminSshHost ?? '');
    final portCtrl = TextEditingController(text: '${e.adminSshPort}');
    final userCtrl = TextEditingController(text: e.adminSshUser ?? 'root');
    final passCtrl = TextEditingController(text: e.adminSshPassword ?? '');
    final adminPortCtrl = TextEditingController(text: '${e.adminApiPort}');
    final tokenCtrl = TextEditingController(text: e.adminToken ?? '');

    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Connect server admin'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'One-time setup, only needed if you deployed this server '
                'yourself. Uses the SSH login and the -admin-token this '
                'server was started with.',
              ),
              const SizedBox(height: 12),
              TextField(
                controller: hostCtrl,
                decoration: const InputDecoration(labelText: 'SSH host/IP'),
              ),
              TextField(
                controller: portCtrl,
                decoration: const InputDecoration(labelText: 'SSH port'),
                keyboardType: TextInputType.number,
              ),
              TextField(
                controller: userCtrl,
                decoration: const InputDecoration(labelText: 'SSH user'),
              ),
              TextField(
                controller: passCtrl,
                decoration: const InputDecoration(labelText: 'SSH password'),
                obscureText: true,
              ),
              TextField(
                controller: adminPortCtrl,
                decoration: const InputDecoration(
                  labelText: 'Admin API port (-admin-listen)',
                ),
                keyboardType: TextInputType.number,
              ),
              TextField(
                controller: tokenCtrl,
                decoration: const InputDecoration(labelText: 'Admin token'),
                obscureText: true,
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (ok != true) return false;
    e.adminSshHost = hostCtrl.text.trim();
    e.adminSshPort = int.tryParse(portCtrl.text.trim()) ?? 22;
    e.adminSshUser = userCtrl.text.trim();
    e.adminSshPassword = passCtrl.text;
    e.adminApiPort = int.tryParse(adminPortCtrl.text.trim()) ?? 8901;
    e.adminToken = tokenCtrl.text.trim();
    return e.hasAdmin;
  }

  void _reorder(int oldIndex, int newIndex) {
    setState(() {
      final item = widget.servers.removeAt(oldIndex);
      widget.servers.insert(newIndex, item);
    });
    widget.onChanged();
  }

  Future<void> _importSubscriptionText(String text) async {
    final lines = text
        .split('\n')
        .map((l) => l.trim())
        .where(
          (l) => l.isNotEmpty && !l.startsWith('#') && !l.startsWith('#!'),
        );
    var imported = 0;
    var failed = 0;
    for (final line in lines) {
      final resultJson = _bindings.parseLink(line);
      final env = jsonDecode(resultJson) as Map<String, dynamic>;
      final err = env['error'] as String? ?? '';
      if (err.isNotEmpty) {
        failed++;
        continue;
      }
      final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
      final label = (p['Tag'] as String?)?.isNotEmpty == true
          ? p['Tag'] as String
          : (p['Host'] as String? ?? 'server');
      widget.servers.add(ServerEntry(id: _newId(), label: label, link: line));
      imported++;
    }
    setState(() {});
    await widget.onChanged();
    if (mounted) {
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            failed == 0
                ? 'Imported $imported server(s)'
                : 'Imported $imported server(s), $failed line(s) failed to parse',
          ),
        ),
      );
    }
  }

  Future<void> _importFromPaste() async {
    final controller = TextEditingController();
    final text = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Import subscription'),
        content: TextField(
          controller: controller,
          maxLines: 8,
          decoration: const InputDecoration(
            hintText: '#!chimera-subscription-v1\nchimera://...\nchimera://...',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(controller.text),
            child: const Text('Import'),
          ),
        ],
      ),
    );
    if (text == null || text.trim().isEmpty) return;
    await _importSubscriptionText(text);
  }

  Future<void> _importFromFile() async {
    const typeGroup = XTypeGroup(label: 'text', extensions: ['txt']);
    final file = await openFile(acceptedTypeGroups: [typeGroup]);
    if (file == null) return;
    final text = await File(file.path).readAsString();
    await _importSubscriptionText(text);
  }

  /// Best-effort parse of a saved link's host:port and transport mode for
  /// display -- purely cosmetic, falls back to the raw link on failure.
  ({String hostPort, String mode}) _parseDisplay(ServerEntry e) {
    try {
      final resultJson = _bindings.parseLink(e.link);
      final env = jsonDecode(resultJson) as Map<String, dynamic>;
      final err = env['error'] as String? ?? '';
      if (err.isNotEmpty) return (hostPort: e.link, mode: '');
      final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
      final host = p['Host'] as String? ?? '';
      final port = p['Port'] as String? ?? '';
      final mode = p['Mode'] as String? ?? '';
      return (hostPort: '$host:$port', mode: mode);
    } catch (_) {
      return (hostPort: e.link, mode: '');
    }
  }

  Widget _pingChip(
    BuildContext context,
    ChimeraTokens tokens,
    ServerPingResult r,
  ) {
    final color = r.ok ? Theme.of(context).colorScheme.primary : tokens.warn;
    return Tooltip(
      message: r.ok ? 'OK' : (r.error.isEmpty ? 'Unreachable' : r.error),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
        decoration: BoxDecoration(
          color: r.ok ? tokens.accentSoft : tokens.dangerSoft,
          borderRadius: BorderRadius.circular(4),
        ),
        child: Text(
          r.ok ? '${r.rttMs} ms' : 'FAIL',
          style: monoStyle(fontSize: 10.5, weight: FontWeight.w600, color: color),
        ),
      ),
    );
  }

  Widget _iconBtn({
    required IconData icon,
    required String tooltip,
    required VoidCallback onPressed,
  }) {
    return Tooltip(
      message: tooltip,
      child: SizedBox(
        width: 30,
        height: 30,
        child: IconButton(
          icon: Icon(icon, size: 17),
          padding: EdgeInsets.zero,
          style: IconButton.styleFrom(
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          ),
          onPressed: onPressed,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      appBar: AppBar(
        title: const Text('Servers'),
        actions: [
          if (_pinging)
            const Padding(
              padding: EdgeInsets.symmetric(horizontal: 10),
              child: SizedBox(
                width: 16,
                height: 16,
                child: CircularProgressIndicator(strokeWidth: 2),
              ),
            )
          else
            _iconBtn(
              icon: Icons.network_ping_outlined,
              tooltip: 'Ping all servers',
              onPressed: _pingServers,
            ),
          const SizedBox(width: 4),
          _iconBtn(
            icon: Icons.file_upload_outlined,
            tooltip: 'Import subscription file',
            onPressed: _importFromFile,
          ),
          const SizedBox(width: 4),
          _iconBtn(
            icon: Icons.paste_outlined,
            tooltip: 'Paste subscription text',
            onPressed: _importFromPaste,
          ),
          const SizedBox(width: 4),
          _iconBtn(
            icon: Icons.rocket_launch_outlined,
            tooltip: 'Deploy new server (install on a bare VPS over SSH)',
            onPressed: _deployNew,
          ),
          const SizedBox(width: 4),
          _iconBtn(
            icon: Icons.add,
            tooltip: 'Add server (link/manual)',
            onPressed: () => _addOrEdit(),
          ),
          const SizedBox(width: 8),
        ],
      ),
      body: widget.servers.isEmpty
          ? Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.dns_outlined, size: 32, color: tokens.textFaint),
                  const SizedBox(height: 10),
                  Text(
                    'No servers yet. Tap + to add one.',
                    style: TextStyle(
                      fontFamily: 'Plex Sans',
                      fontSize: 13,
                      color: tokens.textMuted,
                    ),
                  ),
                ],
              ),
            )
          : ReorderableListView.builder(
              padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
              itemCount: widget.servers.length,
              onReorderItem: _reorder,
              itemBuilder: (context, index) {
                final e = widget.servers[index];
                final display = _parseDisplay(e);
                final mode = display.mode.toLowerCase();
                final isQuic = mode == 'quic';
                return Padding(
                  key: ValueKey(e.id),
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Material(
                    color: Colors.transparent,
                    child: InkWell(
                      borderRadius: BorderRadius.circular(12),
                      onTap: () => _addOrEdit(existing: e),
                      child: Container(
                        padding: const EdgeInsets.symmetric(
                          horizontal: 12,
                          vertical: 10,
                        ),
                        decoration: BoxDecoration(
                          borderRadius: BorderRadius.circular(12),
                          border: Border.all(
                            color: Theme.of(context).dividerColor,
                          ),
                        ),
                        child: Row(
                          children: [
                            SizedBox(
                              width: 20,
                              child: Text(
                                '${index + 1}',
                                style: monoStyle(
                                  fontSize: 11,
                                  color: tokens.textFaint,
                                ),
                              ),
                            ),
                            const SizedBox(width: 8),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Row(
                                    children: [
                                      Flexible(
                                        child: Text(
                                          e.label.isNotEmpty ? e.label : e.link,
                                          overflow: TextOverflow.ellipsis,
                                          style: TextStyle(
                                            fontFamily: 'Plex Sans',
                                            fontSize: 13.5,
                                            fontWeight: FontWeight.w500,
                                            color: Theme.of(
                                              context,
                                            ).colorScheme.onSurface,
                                          ),
                                        ),
                                      ),
                                      if (mode.isNotEmpty) ...[
                                        const SizedBox(width: 6),
                                        Container(
                                          padding: const EdgeInsets.symmetric(
                                            horizontal: 6,
                                            vertical: 2,
                                          ),
                                          decoration: BoxDecoration(
                                            color: isQuic
                                                ? tokens.accentSoft
                                                : tokens.neutralPill,
                                            borderRadius: BorderRadius.circular(
                                              4,
                                            ),
                                          ),
                                          child: Text(
                                            mode.toUpperCase(),
                                            style: TextStyle(
                                              fontFamily: 'Plex Sans',
                                              fontSize: 10.5,
                                              fontWeight: FontWeight.w600,
                                              letterSpacing: 0.4,
                                              color: isQuic
                                                  ? Theme.of(
                                                      context,
                                                    ).colorScheme.primary
                                                  : tokens.textMuted,
                                            ),
                                          ),
                                        ),
                                      ],
                                      if (_pingResults.containsKey(e.id)) ...[
                                        const SizedBox(width: 6),
                                        _pingChip(
                                          context,
                                          tokens,
                                          _pingResults[e.id]!,
                                        ),
                                      ],
                                    ],
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    display.hostPort,
                                    maxLines: 1,
                                    overflow: TextOverflow.ellipsis,
                                    style: monoStyle(
                                      fontSize: 11.5,
                                      color: tokens.textFaint,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            IconButton(
                              icon: const Icon(
                                Icons.group_outlined,
                                size: 18,
                              ),
                              tooltip: 'Manage users / invite someone',
                              onPressed: () => _manageUsers(e),
                            ),
                            IconButton(
                              icon: const Icon(Icons.delete_outline, size: 18),
                              onPressed: () => _remove(e),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                );
              },
            ),
    );
  }
}
