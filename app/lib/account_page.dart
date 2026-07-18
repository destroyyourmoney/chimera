import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'account_store.dart';
import 'catalog_cache_store.dart';
import 'settings_store.dart';
import 'theme.dart';

class AccountPage extends StatefulWidget {
  const AccountPage({
    super.key,
    required this.account,
    required this.onLoggedOut,
    this.embedded = false,
  });

  final AccountInfo account;

  final Future<void> Function() onLoggedOut;

  final bool embedded;

  @override
  State<AccountPage> createState() => _AccountPageState();
}

class _AccountPageState extends State<AccountPage> {
  final _store = AccountStore();
  bool _revealed = false;
  bool _busy = false;

  Future<void> _copy() async {
    await Clipboard.setData(ClipboardData(text: widget.account.numberMasked));
    if (mounted) {
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('Copied to clipboard')));
    }
  }

  Future<void> _confirmLogout() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Log out?'),
        content: const Text(
          'This removes the local access token, saved server selection, '
          'favorites, and cached catalog from this device. You can log '
          'back in any time with the same account number.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(ctx).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(ctx).pop(true),
            child: const Text('Log out'),
          ),
        ],
      ),
    );
    if (ok != true) return;
    setState(() => _busy = true);
    try {
      await _store.logout();
      await SettingsStore().clearServerSelectionState();
      await CatalogCacheStore().clear();
      await widget.onLoggedOut();
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  String _fmtDate(DateTime d) =>
      '${d.year}-${d.month.toString().padLeft(2, '0')}-${d.day.toString().padLeft(2, '0')}';

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final a = widget.account;
    final content = SafeArea(
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 12, 16, 16),
        children: [
          Text(
            'ACCOUNT NUMBER',
            style: monoStyle(
              fontSize: 11,
              weight: FontWeight.w600,
              color: tokens.textFaint,
            ),
          ),
          const SizedBox(height: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
            decoration: BoxDecoration(
              color: tokens.surface2,
              borderRadius: BorderRadius.circular(11),
              border: Border.all(color: Theme.of(context).dividerColor),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    _revealed
                        ? a.numberMasked
                        : '•••• •••• •••• ${a.numberMasked.substring(a.numberMasked.length - 4)}',
                    style: monoStyle(
                      fontSize: 15,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                  ),
                ),
                IconButton(
                  icon: Icon(
                    _revealed
                        ? Icons.visibility_off_outlined
                        : Icons.visibility_outlined,
                    size: 18,
                    color: tokens.textFaint,
                  ),
                  onPressed: () => setState(() => _revealed = !_revealed),
                ),
                IconButton(
                  icon: Icon(
                    Icons.copy_outlined,
                    size: 17,
                    color: tokens.textFaint,
                  ),
                  onPressed: _copy,
                ),
              ],
            ),
          ),
          const SizedBox(height: 20),
          _kvRow(
            context,
            tokens,
            'Status',
            a.status.name[0].toUpperCase() + a.status.name.substring(1),
            valueColor: Theme.of(context).colorScheme.primary,
          ),
          _kvRow(context, tokens, 'Expires', _fmtDate(a.expiresAt), mono: true),
          _kvRow(
            context,
            tokens,
            'Devices',
            '${a.deviceCount} / ${a.deviceLimit}',
            mono: true,
          ),
          const SizedBox(height: 28),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton(
              onPressed: _busy ? null : _confirmLogout,
              child: _busy
                  ? const SizedBox(
                      width: 18,
                      height: 18,
                      child: CircularProgressIndicator(strokeWidth: 2),
                    )
                  : const Text('Log out'),
            ),
          ),
        ],
      ),
    );
    if (widget.embedded) return content;
    return Scaffold(
      appBar: AppBar(title: const Text('Account')),
      body: content,
    );
  }

  Widget _kvRow(
    BuildContext context,
    ChimeraTokens tokens,
    String label,
    String value, {
    Color? valueColor,
    bool mono = false,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 12),
      decoration: BoxDecoration(
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: TextStyle(
              fontFamily: 'Plex Sans',
              fontSize: 13,
              color: tokens.textMuted,
            ),
          ),
          Text(
            value,
            style: mono
                ? monoStyle(
                    fontSize: 13,
                    weight: FontWeight.w500,
                    color:
                        valueColor ?? Theme.of(context).colorScheme.onSurface,
                  )
                : TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 13,
                    fontWeight: FontWeight.w600,
                    color:
                        valueColor ?? Theme.of(context).colorScheme.onSurface,
                  ),
          ),
        ],
      ),
    );
  }
}
