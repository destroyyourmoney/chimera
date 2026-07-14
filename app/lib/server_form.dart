// Add/edit form for a single server entry: builds a chimera:// link
// client-side from typed fields (host/port/pbk/sid/sni/fp/mode/tag), or lets
// the operator paste a raw link directly. Editing an existing entry
// round-trips it through ChimeraBindings.parseLink to prefill the form --
// the same JSON shape internal/api.ParseLinkJSON emits
// (Host/Port/Pbk/Sid/Sni/Fp/Mode/Tag).
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'chimera_bindings.dart';
import 'settings_store.dart';

/// Fingerprint names matching internal/reality.fingerprintByName's known set.
const kFingerprints = [
  'chrome',
  'chrome131',
  'chrome120',
  'firefox',
  'safari',
  'ios',
  'edge',
];

/// Transport modes matching link.Profile.Mode / carrier.Config.Mode.
const kTransportModes = ['auto', 'quic', 'tcp'];

class ServerFormResult {
  ServerFormResult({required this.label, required this.link});
  final String label;
  final String link;
}

class ServerFormPage extends StatefulWidget {
  const ServerFormPage({super.key, this.existing});

  /// existing is the entry being edited, or null when adding a new one.
  final ServerEntry? existing;

  @override
  State<ServerFormPage> createState() => _ServerFormPageState();
}

class _ServerFormPageState extends State<ServerFormPage> {
  final _bindings = ChimeraBindings.open();
  final _formKey = GlobalKey<FormState>();

  final _labelCtrl = TextEditingController();
  final _hostCtrl = TextEditingController();
  final _portCtrl = TextEditingController(text: '443');
  final _pbkCtrl = TextEditingController();
  final _sidCtrl = TextEditingController();
  final _sniCtrl = TextEditingController();
  final _tagCtrl = TextEditingController();
  String _fp = kFingerprints.first;
  String _mode = kTransportModes.first;

  final _pasteCtrl = TextEditingController();
  // Paste/QR is the primary flow: most users have no idea what a public key,
  // short ID, or SNI is and shouldn't need to. The manual form stays available
  // ("Use form") for operators who need it.
  bool _pasteMode = true;
  String? _pasteError;
  bool _detectedFromClipboard = false;

  @override
  void initState() {
    super.initState();
    final existing = widget.existing;
    if (existing != null) {
      _labelCtrl.text = existing.label;
      _prefillFromLink(existing.link);
    } else {
      _maybePrefillFromClipboard();
    }
  }

  // Auto-fill from clipboard if it already contains a chimera:// link (e.g.
  // the user just copied it from the server operator/QR-scanning app) so
  // adding a server can be a single tap on "Save".
  Future<void> _maybePrefillFromClipboard() async {
    final data = await Clipboard.getData('text/plain');
    final text = data?.text?.trim();
    if (text == null || !text.startsWith('chimera://')) return;
    final resultJson = _bindings.parseLink(text);
    final env = jsonDecode(resultJson) as Map<String, dynamic>;
    if ((env['error'] as String? ?? '').isNotEmpty) return;
    if (!mounted) return;
    setState(() {
      _pasteCtrl.text = text;
      _detectedFromClipboard = true;
    });
  }

  void _prefillFromLink(String link) {
    try {
      final resultJson = _bindings.parseLink(link);
      final env = jsonDecode(resultJson) as Map<String, dynamic>;
      final err = env['error'] as String? ?? '';
      if (err.isNotEmpty) return;
      final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
      _hostCtrl.text = p['Host'] as String? ?? '';
      _portCtrl.text = p['Port'] as String? ?? '443';
      _pbkCtrl.text = p['Pbk'] as String? ?? '';
      _sidCtrl.text = p['Sid'] as String? ?? '';
      _sniCtrl.text = p['Sni'] as String? ?? '';
      _tagCtrl.text = p['Tag'] as String? ?? '';
      final fp = p['Fp'] as String? ?? '';
      if (kFingerprints.contains(fp)) _fp = fp;
      final mode = p['Mode'] as String? ?? '';
      if (kTransportModes.contains(mode)) _mode = mode;
    } catch (_) {
      // Unparseable existing link: leave fields blank, operator can retype.
    }
  }

  String _buildLink() {
    final port = int.tryParse(_portCtrl.text.trim());
    return Uri(
      scheme: 'chimera',
      host: _hostCtrl.text.trim(),
      port: port,
      queryParameters: {
        if (_pbkCtrl.text.trim().isNotEmpty) 'pbk': _pbkCtrl.text.trim(),
        if (_sidCtrl.text.trim().isNotEmpty) 'sid': _sidCtrl.text.trim(),
        if (_sniCtrl.text.trim().isNotEmpty) 'sni': _sniCtrl.text.trim(),
        'fp': _fp,
        'mode': _mode,
      },
      fragment: _tagCtrl.text.trim().isNotEmpty ? _tagCtrl.text.trim() : null,
    ).toString();
  }

  void _submitForm() {
    if (!_formKey.currentState!.validate()) return;
    final link = _buildLink();
    final label = _labelCtrl.text.trim().isNotEmpty
        ? _labelCtrl.text.trim()
        : _hostCtrl.text.trim();
    Navigator.of(context).pop(ServerFormResult(label: label, link: link));
  }

  void _submitPaste() {
    final link = _pasteCtrl.text.trim();
    if (link.isEmpty) return;
    final resultJson = _bindings.parseLink(link);
    final env = jsonDecode(resultJson) as Map<String, dynamic>;
    final err = env['error'] as String? ?? '';
    if (err.isNotEmpty) {
      setState(() => _pasteError = err);
      return;
    }
    final p = jsonDecode(env['result'] as String) as Map<String, dynamic>;
    final label = _labelCtrl.text.trim().isNotEmpty
        ? _labelCtrl.text.trim()
        : (p['Host'] as String? ?? 'server');
    Navigator.of(context).pop(ServerFormResult(label: label, link: link));
  }

  @override
  void dispose() {
    _labelCtrl.dispose();
    _hostCtrl.dispose();
    _portCtrl.dispose();
    _pbkCtrl.dispose();
    _sidCtrl.dispose();
    _sniCtrl.dispose();
    _tagCtrl.dispose();
    _pasteCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(widget.existing == null ? 'Add server' : 'Edit server'),
        actions: [
          TextButton(
            onPressed: () => setState(() => _pasteMode = !_pasteMode),
            child: Text(_pasteMode ? 'Use form' : 'Paste link'),
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: _pasteMode ? _buildPasteView() : _buildFormView(),
      ),
    );
  }

  Widget _buildPasteView() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (_detectedFromClipboard)
          Padding(
            padding: const EdgeInsets.only(bottom: 12),
            child: Text(
              'Server link detected from clipboard — just tap Save.',
              style: TextStyle(color: Theme.of(context).colorScheme.primary),
            ),
          ),
        TextField(
          controller: _labelCtrl,
          decoration: const InputDecoration(labelText: 'Label (optional)'),
        ),
        const SizedBox(height: 12),
        TextField(
          controller: _pasteCtrl,
          decoration: InputDecoration(
            labelText: 'chimera:// link or scan QR',
            errorText: _pasteError,
          ),
          maxLines: 3,
        ),
        const SizedBox(height: 16),
        FilledButton(onPressed: _submitPaste, child: const Text('Save')),
      ],
    );
  }

  Widget _buildFormView() {
    return Form(
      key: _formKey,
      child: ListView(
        children: [
          TextFormField(
            controller: _labelCtrl,
            decoration: const InputDecoration(labelText: 'Label (optional)'),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _hostCtrl,
            decoration: const InputDecoration(labelText: 'Host'),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? 'Required' : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _portCtrl,
            decoration: const InputDecoration(labelText: 'Port'),
            keyboardType: TextInputType.number,
            validator: (v) => int.tryParse(v?.trim() ?? '') == null
                ? 'Must be a number'
                : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _pbkCtrl,
            decoration: const InputDecoration(labelText: 'Public key (pbk)'),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? 'Required' : null,
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _sidCtrl,
            decoration: const InputDecoration(
              labelText: 'Short ID (sid, optional)',
            ),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _sniCtrl,
            decoration: const InputDecoration(labelText: 'SNI (steal-host)'),
            validator: (v) =>
                (v == null || v.trim().isEmpty) ? 'Required' : null,
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: _fp,
            decoration: const InputDecoration(labelText: 'Fingerprint'),
            items: kFingerprints
                .map((f) => DropdownMenuItem(value: f, child: Text(f)))
                .toList(),
            onChanged: (v) => setState(() => _fp = v ?? _fp),
          ),
          const SizedBox(height: 12),
          DropdownButtonFormField<String>(
            initialValue: _mode,
            decoration: const InputDecoration(labelText: 'Transport'),
            items: kTransportModes
                .map((m) => DropdownMenuItem(value: m, child: Text(m)))
                .toList(),
            onChanged: (v) => setState(() => _mode = v ?? _mode),
          ),
          const SizedBox(height: 12),
          TextFormField(
            controller: _tagCtrl,
            decoration: const InputDecoration(labelText: 'Tag (optional)'),
          ),
          const SizedBox(height: 20),
          FilledButton(onPressed: _submitForm, child: const Text('Save')),
        ],
      ),
    );
  }
}
