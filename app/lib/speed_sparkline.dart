// Lightweight bytes/sec sparkline: no charting dependency, just a
// CustomPainter drawing a polyline (plus a soft gradient area fill and an
// emphasized endpoint dot) over the last ~30 samples.
import 'package:flutter/material.dart';

class SpeedSparkline extends StatelessWidget {
  const SpeedSparkline({
    super.key,
    required this.samples,
    this.color,
    this.height = 32,
  });

  /// samples is oldest-first; only the tail (up to ~30) is drawn.
  final List<double> samples;
  final Color? color;
  final double height;

  @override
  Widget build(BuildContext context) {
    final c = color ?? Theme.of(context).colorScheme.primary;
    return SizedBox(
      height: height,
      width: double.infinity,
      child: CustomPaint(painter: _SparklinePainter(samples, c)),
    );
  }
}

class _SparklinePainter extends CustomPainter {
  _SparklinePainter(this.samples, this.color);
  final List<double> samples;
  final Color color;

  @override
  void paint(Canvas canvas, Size size) {
    if (samples.length < 2) return;
    final maxVal = samples.reduce((a, b) => a > b ? a : b);
    final scale = maxVal <= 0 ? 0.0 : size.height / maxVal;
    final dx = size.width / (samples.length - 1);

    final points = <Offset>[
      for (var i = 0; i < samples.length; i++)
        Offset(dx * i, size.height - samples[i] * scale),
    ];

    // Soft gradient area fill under the line, closed down to the baseline.
    final areaPath = Path()..moveTo(points.first.dx, size.height);
    for (final p in points) {
      areaPath.lineTo(p.dx, p.dy);
    }
    areaPath.lineTo(points.last.dx, size.height);
    areaPath.close();

    final areaPaint = Paint()
      ..shader = LinearGradient(
        begin: Alignment.topCenter,
        end: Alignment.bottomCenter,
        colors: [color.withValues(alpha: 0.35), color.withValues(alpha: 0.0)],
      ).createShader(Rect.fromLTWH(0, 0, size.width, size.height));
    canvas.drawPath(areaPath, areaPaint);

    // Stroke line.
    final linePath = Path()..moveTo(points.first.dx, points.first.dy);
    for (final p in points.skip(1)) {
      linePath.lineTo(p.dx, p.dy);
    }
    final linePaint = Paint()
      ..color = color
      ..strokeWidth = 1.5
      ..style = PaintingStyle.stroke;
    canvas.drawPath(linePath, linePaint);

    // Emphasized endpoint at the last (rightmost / most current) sample.
    final endpointPaint = Paint()
      ..color = color
      ..style = PaintingStyle.fill;
    canvas.drawCircle(points.last, 3, endpointPaint);
  }

  @override
  bool shouldRepaint(covariant _SparklinePainter oldDelegate) =>
      oldDelegate.samples != samples || oldDelegate.color != color;
}
