import 'package:flutter/material.dart';
import 'package:window_manager/window_manager.dart';

import 'theme.dart';

class MinimalTitlebar extends StatelessWidget {
  const MinimalTitlebar({super.key});

  @override
  Widget build(BuildContext context) {
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    return Container(
      height: 40,
      decoration: BoxDecoration(
        color: tokens.bgWash,
        border: Border(
          bottom: BorderSide(color: Theme.of(context).dividerColor),
        ),
      ),
      child: Row(
        children: [
          Expanded(child: DragToMoveArea(child: Container())),
          _winBtn(
            context,
            tokens,
            icon: Icons.remove,
            onTap: () => windowManager.minimize(),
          ),
          _winBtn(
            context,
            tokens,
            icon: Icons.crop_square,
            onTap: () async {
              if (await windowManager.isMaximized()) {
                await windowManager.unmaximize();
              } else {
                await windowManager.maximize();
              }
            },
          ),
          _winBtn(
            context,
            tokens,
            icon: Icons.close,
            danger: true,
            onTap: () => windowManager.close(),
          ),
        ],
      ),
    );
  }

  Widget _winBtn(
    BuildContext context,
    ChimeraTokens tokens, {
    required IconData icon,
    required VoidCallback onTap,
    bool danger = false,
  }) {
    return SizedBox(
      width: 42,
      height: 40,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          hoverColor: danger ? tokens.dangerSoft : tokens.surface2,
          onTap: onTap,
          child: Icon(icon, size: 14, color: tokens.textFaint),
        ),
      ),
    );
  }
}
