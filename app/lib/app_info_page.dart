import 'package:flutter/material.dart';

import 'app_info.dart';
import 'theme.dart';

class AppInfoPage extends StatelessWidget {
  const AppInfoPage({super.key, this.embedded = false});

  final bool embedded;

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final content = ListView(
      padding: const EdgeInsets.fromLTRB(20, 16, 20, 24),
      children: [
        Text(
          'CHIMERA',
          style: TextStyle(
            fontFamily: 'Plex Sans',
            fontSize: 18,
            fontWeight: FontWeight.w600,
            color: Theme.of(context).colorScheme.onSurface,
          ),
        ),
        const SizedBox(height: 2),
        Text(
          'Version $kAppVersion (build $kAppBuild)',
          style: monoStyle(fontSize: 12.5, color: tokens.textFaint),
        ),
        const SizedBox(height: 16),
        Text(
          'Looks like HTTPS. Isn\'t. A VLESS-Reality/Hysteria2-class '
          'stealth transport with a Windows tray client.',
          style: TextStyle(
            fontFamily: 'Plex Sans',
            fontSize: 12.5,
            color: tokens.textMuted,
            height: 1.4,
          ),
        ),
      ],
    );
    if (embedded) return content;
    return Scaffold(
      appBar: AppBar(title: const Text('App info')),
      body: content,
    );
  }
}
