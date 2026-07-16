// First-launch screen (ROADMAP2 §4): enter the 16-character account key,
// grouped 4x4, and redeem it for local access. `main.dart` decides whether to
// show this or go straight to HomePage based on `AccountStore.hasValidToken`.
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'account_store.dart';
import 'theme.dart';

class AccountEntryPage extends StatefulWidget {
  const AccountEntryPage({super.key, required this.onRedeemed});

  /// Called after a successful redeem; the caller (main.dart) is
  /// responsible for navigating on to HomePage.
  final Future<void> Function(AccountInfo account) onRedeemed;

  @override
  State<AccountEntryPage> createState() => _AccountEntryPageState();
}

class _AccountEntryPageState extends State<AccountEntryPage> {
  final _controller = TextEditingController();
  final _focusNode = FocusNode();
  final _store = AccountStore();
  String? _error;
  bool _busy = false;

  @override
  void dispose() {
    _controller.dispose();
    _focusNode.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    if (_busy) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final result = await _store.redeem(_controller.text);
      if (!result.ok) {
        setState(() => _error = result.error);
        return;
      }
      await widget.onRedeemed(result.account!);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  /// Renders the key as 4 fixed-width groups (filled / caret / empty),
  /// matching the redesign mockup -- a single underlying TextField supplies
  /// the actual input and keyboard handling, kept invisible and focus-only.
  Widget _buildKeyGroups(BuildContext context, ChimeraTokens tokens) {
    final normalized = normalizeAccountNumber(_controller.text)
        .replaceAll('-', '');
    final groups = List.generate(4, (i) {
      final start = i * 4;
      final end = (start + 4).clamp(0, normalized.length);
      return start < normalized.length ? normalized.substring(start, end) : '';
    });
    final activeGroup = (normalized.length ~/ 4).clamp(0, 3);

    return Row(
      children: List.generate(4, (i) {
        final text = groups[i];
        final isActive = i == activeGroup && normalized.length < 16;
        final isFilled = text.length == 4;
        return Expanded(
          child: Padding(
            padding: EdgeInsets.only(left: i == 0 ? 0 : 6),
            child: AnimatedContainer(
              duration: ChimeraMotion.fast,
              padding: const EdgeInsets.symmetric(vertical: 13),
              decoration: BoxDecoration(
                color: tokens.surface2,
                borderRadius: BorderRadius.circular(11),
                border: Border.all(
                  color: isActive
                      ? Theme.of(context).colorScheme.primary
                      : (isFilled
                            ? Theme.of(context).colorScheme.primary
                                  .withValues(alpha: 0.45)
                            : Theme.of(context).dividerColor),
                  width: isActive ? 1.5 : 1,
                ),
              ),
              child: Text(
                text.padRight(4, '·'),
                textAlign: TextAlign.center,
                style: monoStyle(
                  fontSize: 14,
                  weight: FontWeight.w500,
                  color: text.isEmpty
                      ? tokens.textFaint
                      : Theme.of(context).colorScheme.onSurface,
                ),
              ),
            ),
          ),
        );
      }),
    );
  }

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Scaffold(
      body: SafeArea(
        child: GestureDetector(
          behavior: HitTestBehavior.opaque,
          onTap: () => _focusNode.requestFocus(),
          child: Padding(
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 24),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      width: 26,
                      height: 26,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(7),
                        gradient: LinearGradient(
                          begin: Alignment.topLeft,
                          end: Alignment.bottomRight,
                          colors: [
                            Theme.of(context).colorScheme.primary,
                            Theme.of(context).colorScheme.primary,
                            tokens.surface2,
                          ],
                          stops: const [0.0, 0.4, 0.4],
                        ),
                      ),
                    ),
                    const SizedBox(width: 10),
                    Text(
                      'CHIMERA',
                      style: TextStyle(
                        fontFamily: 'Plex Sans',
                        fontWeight: FontWeight.w600,
                        fontSize: 15,
                        color: Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 36),
                Text(
                  'Enter your account number',
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontWeight: FontWeight.w600,
                    fontSize: 20,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
                const SizedBox(height: 8),
                Text(
                  'Your 16-character key unlocks the curated server list. '
                  'No email, no password -- just the key.',
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 13,
                    height: 1.4,
                    color: tokens.textMuted,
                  ),
                ),
                const SizedBox(height: 28),
                Text(
                  'ACCOUNT NUMBER',
                  style: monoStyle(
                    fontSize: 11,
                    weight: FontWeight.w600,
                    color: tokens.textFaint,
                  ),
                ),
                const SizedBox(height: 8),
                Stack(
                  children: [
                    _buildKeyGroups(context, tokens),
                    // Invisible field: owns focus/keyboard/paste, the groups
                    // above are pure display driven by its text.
                    Opacity(
                      opacity: 0,
                      child: TextField(
                        controller: _controller,
                        focusNode: _focusNode,
                        autofocus: true,
                        maxLength: 19,
                        inputFormatters: [
                          FilteringTextInputFormatter.allow(
                            RegExp(r'[A-Za-z0-9\-]'),
                          ),
                        ],
                        decoration: const InputDecoration(counterText: ''),
                        onChanged: (_) => setState(() => _error = null),
                        onSubmitted: (_) => _submit(),
                      ),
                    ),
                  ],
                ),
                if (_error != null) ...[
                  const SizedBox(height: 10),
                  Text(
                    _error!,
                    style: TextStyle(
                      fontFamily: 'Plex Sans',
                      fontSize: 12,
                      color: Theme.of(context).colorScheme.error,
                    ),
                  ),
                ] else ...[
                  const SizedBox(height: 10),
                  Text(
                    'Groups of 4, Base32 (Crockford). The key is issued once --'
                    ' keep it like a password.',
                    style: TextStyle(
                      fontFamily: 'Plex Sans',
                      fontSize: 11.5,
                      height: 1.4,
                      color: tokens.textFaint,
                    ),
                  ),
                ],
                const Spacer(),
                Text(
                  'If the main address is blocked, CHIMERA automatically '
                  'tries signed mirror addresses to reach the account '
                  'service.',
                  style: TextStyle(
                    fontFamily: 'Plex Sans',
                    fontSize: 11.5,
                    height: 1.4,
                    color: tokens.textFaint,
                  ),
                ),
                const SizedBox(height: 14),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: _busy ? null : _submit,
                    child: _busy
                        ? const SizedBox(
                            width: 18,
                            height: 18,
                            child: CircularProgressIndicator(strokeWidth: 2),
                          )
                        : const Text('Continue'),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
