// "Deploy new server" wizard: for an operator who has a bare, freshly
// rented VPS (just an IP and root SSH login) and nothing installed yet --
// the counterpart to server_form.dart's paste/manual flow, which assumes a
// chimera:// link (and therefore a public key + short ID) already exists.
// This screen collects only the SSH login, ships it to
// ChimeraBindings.deployServer (desktop/cffi's ChimeraDeployServer, backed
// by internal/provision.SSHDeployer), which installs Docker, builds the
// CHIMERA server image, and generates the Reality keypair on the VPS itself
// -- the public key and short ID are never typed by hand.
import 'dart:convert';
import 'dart:isolate';

import 'package:flutter/material.dart';

import 'chimera_bindings.dart';
import 'server_form.dart';

/// _deployServerInIsolate is a top-level function, not a closure -- required
/// so Isolate.spawn's entry point is "sendable". A closure declared inside
/// _ServerDeployPageState (even one that only textually reads a local
/// String) can end up capturing the whole State's context, including
/// TextEditingControllers and Flutter binding objects, which are not
/// sendable and make the isolate call fail at runtime with "object is
/// unsendable". Mirrors _startSocksInIsolate in chimera_service.dart.
void _deployServerInIsolate(List<Object> args) {
  final specJson = args[0] as String;
  final sendPort = args[1] as SendPort;
  final bindings = ChimeraBindings.open();
  sendPort.send(bindings.deployServer(specJson));
}

class ServerDeployPage extends StatefulWidget {
  const ServerDeployPage({super.key});

  @override
  State<ServerDeployPage> createState() => _ServerDeployPageState();
}

class _ServerDeployPageState extends State<ServerDeployPage> {
  final _formKey = GlobalKey<FormState>();

  final _labelCtrl = TextEditingController();
  final _hostCtrl = TextEditingController();
  final _sshPortCtrl = TextEditingController(text: '22');
  final _sshUserCtrl = TextEditingController(text: 'root');
  final _sshPasswordCtrl = TextEditingController();
  final _stealHostCtrl = TextEditingController(
    text: 'www.microsoft.com:443',
  );
  final _serverPortCtrl = TextEditingController(text: '443');

  bool _advancedOpen = false;
  bool _deploying = false;
  String? _error;
  String? _hostKeyFingerprint;

  @override
  void dispose() {
    _labelCtrl.dispose();
    _hostCtrl.dispose();
    _sshPortCtrl.dispose();
    _sshUserCtrl.dispose();
    _sshPasswordCtrl.dispose();
    _stealHostCtrl.dispose();
    _serverPortCtrl.dispose();
    super.dispose();
  }

  Future<void> _deploy() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() {
      _deploying = true;
      _error = null;
      _hostKeyFingerprint = null;
    });

    final spec = jsonEncode({
      'host': _hostCtrl.text.trim(),
      'sshPort': int.tryParse(_sshPortCtrl.text.trim()) ?? 22,
      'sshUser': _sshUserCtrl.text.trim(),
      'sshPassword': _sshPasswordCtrl.text,
      'stealHost': _stealHostCtrl.text.trim(),
      'serverPort': int.tryParse(_serverPortCtrl.text.trim()) ?? 443,
    });

    try {
      // deployServer blocks for the whole install (Docker + image build can
      // take minutes) -- spawning a background isolate keeps the UI
      // responsive and satisfies ChimeraNativeApi.deployServer's
      // "background isolate only" contract. Only the spec String and a
      // SendPort cross the isolate boundary; see _deployServerInIsolate's
      // doc comment for why this can't be a plain closure.
      final receivePort = ReceivePort();
      await Isolate.spawn(_deployServerInIsolate, [
        spec,
        receivePort.sendPort,
      ]);
      final resultJson = await receivePort.first as String;
      receivePort.close();
      final env = jsonDecode(resultJson) as Map<String, dynamic>;
      final err = env['error'] as String? ?? '';
      if (err.isNotEmpty) {
        if (!mounted) return;
        setState(() {
          _deploying = false;
          _error = err;
        });
        return;
      }
      final res = jsonDecode(env['result'] as String) as Map<String, dynamic>;
      final links = (res['links'] as List<dynamic>? ?? const [])
          .cast<String>();
      if (links.isEmpty) {
        if (!mounted) return;
        setState(() {
          _deploying = false;
          _error = 'Deployment reported no server links';
        });
        return;
      }
      _hostKeyFingerprint = res['hostKeyFingerprint'] as String?;
      if (!mounted) return;
      final label = _labelCtrl.text.trim().isNotEmpty
          ? _labelCtrl.text.trim()
          : _hostCtrl.text.trim();
      Navigator.of(context).pop(
        ServerFormResult(
          label: label,
          link: links.first,
          adminSshHost: _hostCtrl.text.trim(),
          adminSshPort: int.tryParse(_sshPortCtrl.text.trim()) ?? 22,
          adminSshUser: _sshUserCtrl.text.trim(),
          adminSshPassword: _sshPasswordCtrl.text,
        ),
      );
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _deploying = false;
        _error = e.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Deploy new server')),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: _deploying ? _buildProgress() : _buildForm(),
      ),
    );
  }

  Widget _buildProgress() {
    return const Center(
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          CircularProgressIndicator(),
          SizedBox(height: 16),
          Text(
            'Installing chimera-protocol on your server...\n'
            'This installs Docker and builds the server image, so it can '
            'take a few minutes.',
            textAlign: TextAlign.center,
          ),
        ],
      ),
    );
  }

  Widget _buildForm() {
    return Form(
      key: _formKey,
      child: ListView(
        children: [
          const Text(
            'Point this at a fresh Ubuntu/Debian VPS with root SSH access. '
            'chimera-protocol will be installed and its keys generated on '
            'the server itself -- you never need to know the public key or '
            'short ID.',
          ),
          const SizedBox(height: 16),
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(
                _error!,
                style: TextStyle(color: Theme.of(context).colorScheme.error),
              ),
            ),
          if (_hostKeyFingerprint != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Text(
                'SSH host key fingerprint: $_hostKeyFingerprint\n'
                'Verify this matches what your VPS provider reports.',
              ),
            ),
          TextFormField(
            controller: _labelCtrl,
            decoration: const InputDecoration(labelText: 'Label (optional)'),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _hostCtrl,
            decoration: const InputDecoration(labelText: 'Server host/IP'),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? 'Required' : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _sshUserCtrl,
            decoration: const InputDecoration(labelText: 'SSH user'),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? 'Required' : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _sshPasswordCtrl,
            decoration: const InputDecoration(labelText: 'SSH password'),
            obscureText: true,
          ),
          ExpansionTile(
            title: const Text('Advanced'),
            initiallyExpanded: _advancedOpen,
            onExpansionChanged: (v) => setState(() => _advancedOpen = v),
            children: [
              TextFormField(
                controller: _sshPortCtrl,
                decoration: const InputDecoration(labelText: 'SSH port'),
                keyboardType: TextInputType.number,
                validator: (v) => int.tryParse(v?.trim() ?? '') == null
                    ? 'Must be a number'
                    : null,
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _stealHostCtrl,
                decoration: const InputDecoration(
                  labelText: 'Steal-host (host:port)',
                ),
                validator: (v) =>
                    (v == null || v.trim().isEmpty) ? 'Required' : null,
              ),
              const SizedBox(height: 12),
              TextFormField(
                controller: _serverPortCtrl,
                decoration: const InputDecoration(
                  labelText: 'Server listen port',
                ),
                keyboardType: TextInputType.number,
                validator: (v) => int.tryParse(v?.trim() ?? '') == null
                    ? 'Must be a number'
                    : null,
              ),
            ],
          ),
          const SizedBox(height: 20),
          FilledButton(
            onPressed: _deploy,
            child: const Text('Install & create server'),
          ),
        ],
      ),
    );
  }
}
