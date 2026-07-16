// "Signal core" hero (ROADMAP2 §4 / redesign spec note 01): a pulsing
// abstract core replacing a Mullvad/iVPN-style world map on Home. The
// catalog is curated and deliberately not fleet-enumerable, so this state
// indicator ("Protected"/"Not protected") never draws server topology --
// see the artifact's note "Почему не карта мира". Mirrors the mockup's
// `.signal-core`/`.ring`/`.core-dot` almost exactly: 3 concentric rings
// (150/110/74px) pulsing outward with staggered phase (0 / .4s / .8s over a
// 2.6s loop, easeOut), a glowing center dot when active, both going static
// and desaturated when disconnected.
import 'package:flutter/material.dart';

import 'theme.dart';

class SignalCore extends StatefulWidget {
  const SignalCore({super.key, required this.active});

  final bool active;

  @override
  State<SignalCore> createState() => _SignalCoreState();
}

class _SignalCoreState extends State<SignalCore>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl = AnimationController(
    vsync: this,
    duration: const Duration(milliseconds: 2600),
  );

  @override
  void didChangeDependencies() {
    super.didChangeDependencies();
    _applyMotion();
  }

  @override
  void didUpdateWidget(covariant SignalCore oldWidget) {
    super.didUpdateWidget(oldWidget);
    _applyMotion();
  }

  void _applyMotion() {
    // Respect the artifact's `@media (prefers-reduced-motion: no-preference)`
    // gate: only the *active* pulse is motion, not the state change itself.
    final reduceMotion = MediaQuery.of(context).disableAnimations;
    if (widget.active && !reduceMotion) {
      if (!_ctrl.isAnimating) _ctrl.repeat();
    } else {
      _ctrl.stop();
    }
  }

  @override
  void dispose() {
    _ctrl.dispose();
    super.dispose();
  }

  double _phaseValue(double phaseOffset) => (_ctrl.value + phaseOffset) % 1.0;

  @override
  Widget build(BuildContext context) {
    final scheme = Theme.of(context).colorScheme;
    final tokens = Theme.of(context).extension<ChimeraTokens>()!;
    final ringColor = widget.active ? scheme.primary : tokens.textFaint;

    return SizedBox(
      height: 150,
      child: Center(
        child: AnimatedBuilder(
          animation: _ctrl,
          builder: (context, _) => Stack(
            alignment: Alignment.center,
            children: [
              _pulsingRing(diameter: 150, phase: 0.0, color: ringColor),
              _pulsingRing(
                diameter: 110,
                phase: 0.4 / 2.6,
                color: ringColor,
              ),
              _pulsingRing(
                diameter: 74,
                phase: 0.8 / 2.6,
                color: ringColor,
              ),
              _dot(
                accent: scheme.primary,
                accentSoft: tokens.accentSoft,
                faint: tokens.textFaint,
                faintHalo: tokens.surface2,
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _ringCircle(double diameter, Color color) => Container(
    width: diameter,
    height: diameter,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      border: Border.all(color: color, width: 1),
    ),
  );

  Widget _pulsingRing({
    required double diameter,
    required double phase,
    required Color color,
  }) {
    if (!widget.active) {
      return Opacity(opacity: 0.14, child: _ringCircle(diameter, color));
    }
    final t = _phaseValue(phase);
    final scale = 0.86 + 0.32 * t;
    final opacity = 0.5 * (1 - t);
    return Opacity(
      opacity: opacity.clamp(0.0, 1.0),
      child: Transform.scale(
        scale: scale,
        child: _ringCircle(diameter, color),
      ),
    );
  }

  Widget _dot({
    required Color accent,
    required Color accentSoft,
    required Color faint,
    required Color faintHalo,
  }) {
    final active = widget.active;
    return Container(
      width: 14,
      height: 14,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: active ? accent : faint,
        boxShadow: [
          BoxShadow(color: active ? accentSoft : faintHalo, spreadRadius: 6),
          if (active)
            BoxShadow(
              color: accent.withValues(alpha: 0.6),
              blurRadius: 22,
              spreadRadius: 2,
            ),
        ],
      ),
    );
  }
}
