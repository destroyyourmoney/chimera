// "Manage users" screen for a server you deployed yourself: opens an SSH
// tunnel to that server's loopback-only admin API (internal/admin) and lets
// you add or revoke a chimera:// invite for someone else, without a
// terminal. Each invite reuses this server's own pbk/sni/fp/mode -- only the
// short ID (and a friendly label) differ per person, matching how
// internal/useracl.Store models "users" server-side.
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'admin_api_client.dart';
import 'chimera_bindings.dart';
import 'settings_store.dart';
import 'ssh_admin_tunnel.dart';

class ServerUsersPage extends StatefulWidget {
  const ServerUsersPage({super.key, required this.server});

  final ServerEntry server;

  @override
  State<ServerUsersPage> createState() => _ServerUsersPageState();
}

class _ServerUsersPageState extends State<ServerUsersPage> {
  final _bindings = ChimeraBindings.open();
  final _tunnel = SshAdminTunnel();
  AdminApiClient? _client;

  bool _loading = true;
  String? _error;
  List<AdminUser> _users = [];

  @override
  void initState() {
    super.initState();
    _connect();
  }

  @override
  void dispose() {
    _tunnel.close();
    super.dispose();
  }

  Future<void> _connect() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final localPort = await _tunnel.open(
        host: widget.server.adminSshHost!,
        sshPort: widget.server.adminSshPort,
        user: widget.server.adminSshUser!,
        password: widget.server.adminSshPassword ?? '',
        adminApiPort: widget.server.adminApiPort,
      );
      _client = AdminApiClient(
        localPort: localPort,
        token: widget.server.adminToken!,
      );
      await _refresh();
    } catch (e) {
      if (mounted) setState(() => _error = 'Could not connect: $e');
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  Future<void> _refresh() async {
    final client = _client;
    if (client == null) return;
    final users = await client.listUsers();
    if (mounted) setState(() => _users = users);
  }

  /// Builds a per-user chimera:// link: same host/port/pbk/sni/fp/mode as this
  /// server's own saved link, with only the sid and tag swapped in.
  String? _buildLinkFor(AdminUser u) {
    final resultJson = _bindings.parseLink(widget.server.link);
    final env = jsonDecode(resultJson) as Map<String, dynamic>;
    if ((env['error'] as String? ?? '').isNotEmpty) return null;
    final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
    final port = int.tryParse(p['Port'] as String? ?? '443');
    return Uri(
      scheme: 'chimera',
      host: p['Host'] as String? ?? '',
      port: port,
      queryParameters: {
        'pbk': p['Pbk'] as String? ?? '',
        if ((p['Sni'] as String? ?? '').isNotEmpty) 'sni': p['Sni'] as String,
        'fp': p['Fp'] as String? ?? 'chrome',
        'mode': p['Mode'] as String? ?? 'auto',
        'sid': u.sid,
      },
      fragment: u.label.isNotEmpty ? u.label : null,
    ).toString();
  }

  Future<void> _addUser() async {
    final controller = TextEditingController();
    final label = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Add person'),
        content: TextField(
          controller: controller,
          autofocus: true,
          decoration: const InputDecoration(
            labelText: 'Name (e.g. "Alice\'s phone")',
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(controller.text.trim()),
            child: const Text('Add'),
          ),
        ],
      ),
    );
    if (label == null || label.isEmpty) return;
    final client = _client;
    if (client == null) return;
    try {
      final u = await client.addUser(label);
      await _refresh();
      final link = _buildLinkFor(u);
      if (link != null && mounted) {
        await _showLinkDialog(label, link);
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to add: $e')));
      }
    }
  }

  Future<void> _showLinkDialog(String label, String link) {
    return showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Invite for $label'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text(
              'Send this link to them -- pasting it into "Add server" fills everything in automatically.',
            ),
            const SizedBox(height: 12),
            SelectableText(link, style: const TextStyle(fontFamily: 'Plex Mono', fontSize: 12)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () async {
              await Clipboard.setData(ClipboardData(text: link));
              if (ctx.mounted) Navigator.of(ctx).pop();
            },
            child: const Text('Copy'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(),
            child: const Text('Done'),
          ),
        ],
      ),
    );
  }

  Future<void> _revoke(AdminUser u) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Revoke ${u.label.isNotEmpty ? u.label : u.sid}?'),
        content: const Text(
          'They will be disconnected and their link will stop working immediately.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Revoke'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    final client = _client;
    if (client == null) return;
    try {
      await client.removeUser(u.sid);
      await _refresh();
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(
          context,
        ).showSnackBar(SnackBar(content: Text('Failed to revoke: $e')));
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text('Users on ${widget.server.label}'),
        actions: [
          IconButton(
            icon: const Icon(Icons.person_add_outlined),
            tooltip: 'Add person',
            onPressed: _client == null ? null : _addUser,
          ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator())
          : _error != null
          ? Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(_error!, textAlign: TextAlign.center),
                    const SizedBox(height: 12),
                    FilledButton(
                      onPressed: _connect,
                      child: const Text('Retry'),
                    ),
                  ],
                ),
              ),
            )
          : RefreshIndicator(
              onRefresh: _refresh,
              child: _users.isEmpty
                  ? ListView(
                      children: const [
                        Padding(
                          padding: EdgeInsets.all(24),
                          child: Text(
                            'No one added yet. Tap the + icon to invite someone.',
                            textAlign: TextAlign.center,
                          ),
                        ),
                      ],
                    )
                  : ListView.builder(
                      itemCount: _users.length,
                      itemBuilder: (context, i) {
                        final u = _users[i];
                        return ListTile(
                          title: Text(u.label.isNotEmpty ? u.label : u.sid),
                          subtitle: Text(u.sid),
                          trailing: Row(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              IconButton(
                                icon: const Icon(Icons.link),
                                tooltip: 'Show link again',
                                onPressed: () {
                                  final link = _buildLinkFor(u);
                                  if (link != null) {
                                    _showLinkDialog(
                                      u.label.isNotEmpty ? u.label : u.sid,
                                      link,
                                    );
                                  }
                                },
                              ),
                              IconButton(
                                icon: const Icon(Icons.delete_outline),
                                tooltip: 'Revoke',
                                onPressed: () => _revoke(u),
                              ),
                            ],
                          ),
                        );
                      },
                    ),
            ),
    );
  }
}
