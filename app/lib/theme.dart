// CHIMERA design system: color tokens, typography and themed widget
// defaults shared by every screen. Colors mirror the approved mockup
// exactly (see docs handoff) -- dark is the default/primary theme, light
// is a fully-specified secondary. Extra semantic tokens that don't have a
// slot in Material's ColorScheme (accent-soft, warn/warn-soft,
// danger-soft, neutral-pill, text-faint) live in [ChimeraTokens], a
// ThemeExtension registered on both ThemeDatas.
import 'package:flutter/material.dart';

@immutable
class ChimeraTokens extends ThemeExtension<ChimeraTokens> {
  const ChimeraTokens({
    required this.accentSoft,
    required this.accentInk,
    required this.warn,
    required this.warnSoft,
    required this.dangerSoft,
    required this.neutralPill,
    required this.textFaint,
    required this.textMuted,
    required this.bgWash,
    required this.surface2,
  });

  final Color accentSoft;
  final Color accentInk;
  final Color warn;
  final Color warnSoft;
  final Color dangerSoft;
  final Color neutralPill;
  final Color textFaint;
  final Color textMuted;
  final Color bgWash;
  final Color surface2;

  @override
  ChimeraTokens copyWith({
    Color? accentSoft,
    Color? accentInk,
    Color? warn,
    Color? warnSoft,
    Color? dangerSoft,
    Color? neutralPill,
    Color? textFaint,
    Color? textMuted,
    Color? bgWash,
    Color? surface2,
  }) {
    return ChimeraTokens(
      accentSoft: accentSoft ?? this.accentSoft,
      accentInk: accentInk ?? this.accentInk,
      warn: warn ?? this.warn,
      warnSoft: warnSoft ?? this.warnSoft,
      dangerSoft: dangerSoft ?? this.dangerSoft,
      neutralPill: neutralPill ?? this.neutralPill,
      textFaint: textFaint ?? this.textFaint,
      textMuted: textMuted ?? this.textMuted,
      bgWash: bgWash ?? this.bgWash,
      surface2: surface2 ?? this.surface2,
    );
  }

  @override
  ChimeraTokens lerp(ThemeExtension<ChimeraTokens>? other, double t) {
    if (other is! ChimeraTokens) return this;
    return ChimeraTokens(
      accentSoft: Color.lerp(accentSoft, other.accentSoft, t)!,
      accentInk: Color.lerp(accentInk, other.accentInk, t)!,
      warn: Color.lerp(warn, other.warn, t)!,
      warnSoft: Color.lerp(warnSoft, other.warnSoft, t)!,
      dangerSoft: Color.lerp(dangerSoft, other.dangerSoft, t)!,
      neutralPill: Color.lerp(neutralPill, other.neutralPill, t)!,
      textFaint: Color.lerp(textFaint, other.textFaint, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      bgWash: Color.lerp(bgWash, other.bgWash, t)!,
      surface2: Color.lerp(surface2, other.surface2, t)!,
    );
  }
}

// --- Dark theme tokens (default/primary) -----------------------------
const _darkBg = Color(0xFF0C1512);
const _darkBgWash = Color(0xFF0A110F);
const _darkSurface = Color(0xFF121E19);
const _darkSurface2 = Color(0xFF17251F);
const _darkBorder = Color(0xFF223229);
const _darkTextPrimary = Color(0xFFEAF2EE);
const _darkTextMuted = Color(0xFF92A89D);
const _darkTextFaint = Color(0xFF647A70);
const _darkAccent = Color(0xFF49D6B3);
const _darkAccentInk = Color(0xFF06231B);
const _darkAccentSoft = Color(0xFF163C30);
const _darkWarn = Color(0xFFE8B85A);
const _darkWarnSoft = Color(0xFF3A2F16);
const _darkDanger = Color(0xFFE2604F);
const _darkDangerSoft = Color(0xFF3A1E18);
const _darkNeutralPill = Color(0xFF223029);

// --- Light theme tokens -----------------------------------------------
const _lightBg = Color(0xFFEEF2F0);
const _lightBgWash = Color(0xFFE4E9E6);
const _lightSurface = Color(0xFFFFFFFF);
const _lightSurface2 = Color(0xFFEEF3F0);
const _lightBorder = Color(0xFFD7E0DB);
const _lightTextPrimary = Color(0xFF12201A);
const _lightTextMuted = Color(0xFF5C6F66);
const _lightTextFaint = Color(0xFF8A9B92);
const _lightAccent = Color(0xFF17916F);
const _lightAccentInk = Color(0xFFFFFFFF);
const _lightAccentSoft = Color(0xFFDCF0E8);
const _lightWarn = Color(0xFFA3690F);
const _lightWarnSoft = Color(0xFFF5E6CD);
const _lightDanger = Color(0xFFB23A2B);
const _lightDangerSoft = Color(0xFFF6E0DC);
const _lightNeutralPill = Color(0xFFE4E9E6);

const _fontSans = 'Plex Sans';

InputDecorationTheme _inputTheme({
  required Color fill,
  required Color border,
  required Color accent,
  required Color textFaint,
}) {
  OutlineInputBorder ob(Color c, {double w = 1}) => OutlineInputBorder(
    borderRadius: BorderRadius.circular(11),
    borderSide: BorderSide(color: c, width: w),
  );
  return InputDecorationTheme(
    filled: true,
    fillColor: fill,
    contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
    border: ob(border),
    enabledBorder: ob(border),
    focusedBorder: ob(accent, w: 1.5),
    errorBorder: ob(_darkDanger),
    focusedErrorBorder: ob(_darkDanger, w: 1.5),
    labelStyle: TextStyle(color: textFaint, fontFamily: _fontSans),
    hintStyle: TextStyle(color: textFaint, fontFamily: _fontSans),
  );
}

ThemeData _buildTheme({
  required Brightness brightness,
  required Color bg,
  required Color bgWash,
  required Color surface,
  required Color surface2,
  required Color border,
  required Color textPrimary,
  required Color textMuted,
  required Color textFaint,
  required Color accent,
  required Color accentInk,
  required Color accentSoft,
  required Color warn,
  required Color warnSoft,
  required Color danger,
  required Color dangerSoft,
  required Color neutralPill,
}) {
  final colorScheme = ColorScheme(
    brightness: brightness,
    primary: accent,
    onPrimary: accentInk,
    secondary: accent,
    onSecondary: accentInk,
    error: danger,
    onError: brightness == Brightness.dark ? Colors.white : Colors.white,
    surface: surface,
    onSurface: textPrimary,
    surfaceContainerHighest: surface2,
    outline: border,
    outlineVariant: border,
  );

  final base = brightness == Brightness.dark
      ? ThemeData.dark(useMaterial3: true)
      : ThemeData.light(useMaterial3: true);

  return ThemeData(
    useMaterial3: true,
    brightness: brightness,
    fontFamily: _fontSans,
    scaffoldBackgroundColor: bg,
    colorScheme: colorScheme,
    textTheme: base.textTheme.apply(
      fontFamily: _fontSans,
      bodyColor: textPrimary,
      displayColor: textPrimary,
    ),
    dividerColor: border,
    dividerTheme: DividerThemeData(color: border, thickness: 1, space: 1),
    appBarTheme: AppBarTheme(
      backgroundColor: bg,
      foregroundColor: textPrimary,
      elevation: 0,
      scrolledUnderElevation: 0,
      surfaceTintColor: Colors.transparent,
      titleTextStyle: TextStyle(
        fontFamily: _fontSans,
        fontWeight: FontWeight.w600,
        fontSize: 16,
        color: textPrimary,
      ),
      iconTheme: IconThemeData(color: textPrimary),
    ),
    cardTheme: CardThemeData(
      color: surface2,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: border),
      ),
    ),
    listTileTheme: ListTileThemeData(
      iconColor: textMuted,
      textColor: textPrimary,
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: accent,
        foregroundColor: accentInk,
        disabledBackgroundColor: accent.withValues(alpha: 0.4),
        disabledForegroundColor: accentInk.withValues(alpha: 0.7),
        textStyle: const TextStyle(
          fontFamily: _fontSans,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
        padding: const EdgeInsets.symmetric(vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(11)),
        elevation: 0,
      ),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        backgroundColor: accent,
        foregroundColor: accentInk,
        disabledBackgroundColor: accent.withValues(alpha: 0.4),
        disabledForegroundColor: accentInk.withValues(alpha: 0.7),
        textStyle: const TextStyle(
          fontFamily: _fontSans,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
        padding: const EdgeInsets.symmetric(vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(11)),
        elevation: 0,
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: danger,
        disabledForegroundColor: danger.withValues(alpha: 0.5),
        side: BorderSide(color: danger.withValues(alpha: 0.6)),
        textStyle: const TextStyle(
          fontFamily: _fontSans,
          fontWeight: FontWeight.w600,
          fontSize: 14,
        ),
        padding: const EdgeInsets.symmetric(vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(11)),
      ),
    ),
    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: accent,
        textStyle: const TextStyle(
          fontFamily: _fontSans,
          fontWeight: FontWeight.w600,
          fontSize: 13.5,
        ),
      ),
    ),
    iconTheme: IconThemeData(color: textMuted),
    switchTheme: SwitchThemeData(
      thumbColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) return accentInk;
        return surface;
      }),
      trackColor: WidgetStateProperty.resolveWith((states) {
        if (states.contains(WidgetState.selected)) return accent;
        return neutralPill;
      }),
      trackOutlineColor: WidgetStateProperty.all(Colors.transparent),
    ),
    inputDecorationTheme: _inputTheme(
      fill: surface2,
      border: border,
      accent: accent,
      textFaint: textFaint,
    ),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: surface2,
      contentTextStyle: TextStyle(fontFamily: _fontSans, color: textPrimary),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: surface,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(14)),
    ),
    extensions: [
      ChimeraTokens(
        accentSoft: accentSoft,
        accentInk: accentInk,
        warn: warn,
        warnSoft: warnSoft,
        dangerSoft: dangerSoft,
        neutralPill: neutralPill,
        textFaint: textFaint,
        textMuted: textMuted,
        bgWash: bgWash,
        surface2: surface2,
      ),
    ],
  );
}

final ThemeData chimeraDarkTheme = _buildTheme(
  brightness: Brightness.dark,
  bg: _darkBg,
  bgWash: _darkBgWash,
  surface: _darkSurface,
  surface2: _darkSurface2,
  border: _darkBorder,
  textPrimary: _darkTextPrimary,
  textMuted: _darkTextMuted,
  textFaint: _darkTextFaint,
  accent: _darkAccent,
  accentInk: _darkAccentInk,
  accentSoft: _darkAccentSoft,
  warn: _darkWarn,
  warnSoft: _darkWarnSoft,
  danger: _darkDanger,
  dangerSoft: _darkDangerSoft,
  neutralPill: _darkNeutralPill,
);

final ThemeData chimeraLightTheme = _buildTheme(
  brightness: Brightness.light,
  bg: _lightBg,
  bgWash: _lightBgWash,
  surface: _lightSurface,
  surface2: _lightSurface2,
  border: _lightBorder,
  textPrimary: _lightTextPrimary,
  textMuted: _lightTextMuted,
  textFaint: _lightTextFaint,
  accent: _lightAccent,
  accentInk: _lightAccentInk,
  accentSoft: _lightAccentSoft,
  warn: _lightWarn,
  warnSoft: _lightWarnSoft,
  danger: _lightDanger,
  dangerSoft: _lightDangerSoft,
  neutralPill: _lightNeutralPill,
);

/// Named motion tokens shared by every screen (ROADMAP2 §4): connect/
/// disconnect crossfades, list filtering, and page transitions all read off
/// these instead of ad-hoc literal durations, so pacing stays consistent
/// (and changeable in one place) as new screens land.
abstract final class ChimeraMotion {
  /// Small state toggles: favorite star, transport radio selection.
  static const fast = Duration(milliseconds: 120);

  /// Default: connect/disconnect crossfade, status card recolor.
  static const standard = Duration(milliseconds: 220);

  /// Page-level transitions (catalog <-> home, entry -> home).
  static const emphasized = Duration(milliseconds: 320);

  static const standardCurve = Curves.easeOutCubic;
  static const emphasizedCurve = Curves.easeOutCubic;
}

/// Custom page transition sharing [ChimeraMotion.emphasized]'s duration/curve
/// -- a subtle fade + slide-up instead of Material's default platform
/// transition, used for the account-key gate and catalog/anticensorship
/// pushes so those flows feel like part of one system rather than default
/// MaterialPageRoute chrome.
class ChimeraPageRoute<T> extends PageRouteBuilder<T> {
  ChimeraPageRoute({required WidgetBuilder builder})
    : super(
        pageBuilder: (context, animation, secondaryAnimation) =>
            builder(context),
        transitionDuration: ChimeraMotion.emphasized,
        reverseTransitionDuration: ChimeraMotion.emphasized,
        transitionsBuilder: (context, animation, secondaryAnimation, child) {
          final curved = CurvedAnimation(
            parent: animation,
            curve: ChimeraMotion.emphasizedCurve,
          );
          return FadeTransition(
            opacity: curved,
            child: SlideTransition(
              position: Tween<Offset>(
                begin: const Offset(0, 0.04),
                end: Offset.zero,
              ).animate(curved),
              child: child,
            ),
          );
        },
      );
}

/// Monospace text style for protocol/measurement data (hosts, ports,
/// throughput, RTT, transport labels) -- see design system split between
/// Plex Sans (UI chrome) and Plex Mono (data).
TextStyle monoStyle({
  double fontSize = 12,
  FontWeight weight = FontWeight.w400,
  Color? color,
  bool tabularFigures = true,
}) {
  return TextStyle(
    fontFamily: 'Plex Mono',
    fontSize: fontSize,
    fontWeight: weight,
    color: color,
    fontFeatures: tabularFigures ? const [FontFeature.tabularFigures()] : null,
  );
}
