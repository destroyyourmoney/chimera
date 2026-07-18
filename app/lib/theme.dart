import 'package:flutter/material.dart';

@immutable
class ChimeraTokens extends ThemeExtension<ChimeraTokens> {
  const ChimeraTokens({
    required this.accentSoft,
    required this.accentInk,
    required this.accentText,
    required this.warn,
    required this.warnSoft,
    required this.dangerSoft,
    required this.neutralPill,
    required this.textFaint,
    required this.textMuted,
    required this.bgWash,
    required this.surface2,
    required this.railTop,
    required this.railBottom,
    required this.heroWash,
  });

  final Color accentSoft;
  final Color accentInk;

  final Color accentText;
  final Color warn;
  final Color warnSoft;
  final Color dangerSoft;
  final Color neutralPill;
  final Color textFaint;
  final Color textMuted;
  final Color bgWash;
  final Color surface2;

  final Color railTop;
  final Color railBottom;

  final Color heroWash;

  @override
  ChimeraTokens copyWith({
    Color? accentSoft,
    Color? accentInk,
    Color? accentText,
    Color? warn,
    Color? warnSoft,
    Color? dangerSoft,
    Color? neutralPill,
    Color? textFaint,
    Color? textMuted,
    Color? bgWash,
    Color? surface2,
    Color? railTop,
    Color? railBottom,
    Color? heroWash,
  }) {
    return ChimeraTokens(
      accentSoft: accentSoft ?? this.accentSoft,
      accentInk: accentInk ?? this.accentInk,
      accentText: accentText ?? this.accentText,
      warn: warn ?? this.warn,
      warnSoft: warnSoft ?? this.warnSoft,
      dangerSoft: dangerSoft ?? this.dangerSoft,
      neutralPill: neutralPill ?? this.neutralPill,
      textFaint: textFaint ?? this.textFaint,
      textMuted: textMuted ?? this.textMuted,
      bgWash: bgWash ?? this.bgWash,
      surface2: surface2 ?? this.surface2,
      railTop: railTop ?? this.railTop,
      railBottom: railBottom ?? this.railBottom,
      heroWash: heroWash ?? this.heroWash,
    );
  }

  @override
  ChimeraTokens lerp(ThemeExtension<ChimeraTokens>? other, double t) {
    if (other is! ChimeraTokens) return this;
    return ChimeraTokens(
      accentSoft: Color.lerp(accentSoft, other.accentSoft, t)!,
      accentInk: Color.lerp(accentInk, other.accentInk, t)!,
      accentText: Color.lerp(accentText, other.accentText, t)!,
      warn: Color.lerp(warn, other.warn, t)!,
      warnSoft: Color.lerp(warnSoft, other.warnSoft, t)!,
      dangerSoft: Color.lerp(dangerSoft, other.dangerSoft, t)!,
      neutralPill: Color.lerp(neutralPill, other.neutralPill, t)!,
      textFaint: Color.lerp(textFaint, other.textFaint, t)!,
      textMuted: Color.lerp(textMuted, other.textMuted, t)!,
      bgWash: Color.lerp(bgWash, other.bgWash, t)!,
      surface2: Color.lerp(surface2, other.surface2, t)!,
      railTop: Color.lerp(railTop, other.railTop, t)!,
      railBottom: Color.lerp(railBottom, other.railBottom, t)!,
      heroWash: Color.lerp(heroWash, other.heroWash, t)!,
    );
  }
}

const _pacificDeep = Color(0xFF0B3D57);
const _pacificCore = Color(0xFF0F6E8C);
const _pacificMist = Color(0xFF2C86A6);
const _pacificFoam = Color(0xFFBFE3EC);
const _amberSignal = Color(0xFFE8A23D);
const _coralFail = Color(0xFFE4573F);

abstract final class ChimeraPalette {
  static const pacificDeep = _pacificDeep;
  static const pacificCore = _pacificCore;
  static const pacificMist = _pacificMist;
  static const pacificFoam = _pacificFoam;
  static const amberSignal = _amberSignal;
  static const coralFail = _coralFail;
}

const _darkBg = Color(0xFF0A141C);
const _darkBgWash = Color(0xFF081019);
const _darkSurface = Color(0xFF0E2231);
const _darkSurface2 = Color(0xFF12293B);
const _darkBorder = Color(0xFF1E3A4D);
const _darkTextPrimary = Color(0xFFE9F3F7);
const _darkTextMuted = Color(0xFF8FABB9);
const _darkTextFaint = Color(0xFF5C7A8B);
const _darkAccent = _pacificCore;
const _darkAccentInk = Color(0xFF04141B);
const _darkAccentSoft = Color(0xFF123448);
const _darkAccentText = _pacificFoam;
const _darkWarn = _amberSignal;
const _darkWarnSoft = Color(0xFF3A2C14);
const _darkDanger = _coralFail;
const _darkDangerSoft = Color(0xFF391D17);
const _darkNeutralPill = Color(0xFF1A3244);
const _darkRailTop = _pacificDeep;
const _darkRailBottom = _darkBgWash;
const _darkHeroWash = _pacificDeep;

const _lightBg = Color(0xFFEEF3F4);
const _lightBgWash = Color(0xFFE6EDEE);
const _lightSurface = Color(0xFFFFFFFF);
const _lightSurface2 = Color(0xFFEAF1F4);
const _lightBorder = Color(0xFFD5E2E6);
const _lightTextPrimary = Color(0xFF0E2233);
const _lightTextMuted = Color(0xFF4C6675);
const _lightTextFaint = Color(0xFF7C97A3);
const _lightAccent = _pacificCore;
const _lightAccentInk = Color(0xFFFFFFFF);
const _lightAccentSoft = Color(0xFFDCEDF3);
const _lightAccentText = Color(0xFF0A5573);
const _lightWarn = Color(0xFFA66A1E);
const _lightWarnSoft = Color(0xFFF4E6D1);
const _lightDanger = Color(0xFFB23A2B);
const _lightDangerSoft = Color(0xFFF5E0DC);
const _lightNeutralPill = Color(0xFFE2EAED);
const _lightRailTop = Color(0xFFDCEBF1);
const _lightRailBottom = _lightBgWash;
const _lightHeroWash = Color(0xFFD3E8EE);

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
  required Color accentText,
  required Color warn,
  required Color warnSoft,
  required Color danger,
  required Color dangerSoft,
  required Color neutralPill,
  required Color railTop,
  required Color railBottom,
  required Color heroWash,
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
        accentText: accentText,
        warn: warn,
        warnSoft: warnSoft,
        dangerSoft: dangerSoft,
        neutralPill: neutralPill,
        textFaint: textFaint,
        textMuted: textMuted,
        bgWash: bgWash,
        surface2: surface2,
        railTop: railTop,
        railBottom: railBottom,
        heroWash: heroWash,
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
  accentText: _darkAccentText,
  warn: _darkWarn,
  warnSoft: _darkWarnSoft,
  danger: _darkDanger,
  dangerSoft: _darkDangerSoft,
  neutralPill: _darkNeutralPill,
  railTop: _darkRailTop,
  railBottom: _darkRailBottom,
  heroWash: _darkHeroWash,
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
  accentText: _lightAccentText,
  warn: _lightWarn,
  warnSoft: _lightWarnSoft,
  danger: _lightDanger,
  dangerSoft: _lightDangerSoft,
  neutralPill: _lightNeutralPill,
  railTop: _lightRailTop,
  railBottom: _lightRailBottom,
  heroWash: _lightHeroWash,
);

abstract final class ChimeraMotion {
  static const fast = Duration(milliseconds: 120);

  static const standard = Duration(milliseconds: 220);

  static const emphasized = Duration(milliseconds: 320);

  static const standardCurve = Curves.easeOutCubic;
  static const emphasizedCurve = Curves.easeOutCubic;
}

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
