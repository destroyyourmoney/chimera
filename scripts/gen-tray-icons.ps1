# Regenerates the CHIMERA tray-state icons (connected/disconnected/error) as
# real 32x32 ARGB .ico files, colored from the app's design tokens
# (app/lib/theme.dart). Run after changing tray state colors; output lands in
# app/assets/icons/, which is bundled as a Flutter asset (see pubspec.yaml)
# and resolved at runtime relative to the executable -- NOT copied from
# windows/runner/resources, which is source-tree-only and absent from any
# built app/data/flutter_assets output.
#
# Icons are packed as a single PNG-format frame inside a hand-built ICO
# container (valid on Vista+) instead of via Bitmap.GetHicon(), which routes
# through legacy GDI and quantizes true-color ARGB down to a reduced system
# palette -- that quantization is what produced banded/wrong colors on the
# first attempt.
Add-Type -AssemblyName System.Drawing

function New-DotIcon {
    param(
        [string]$Path,
        [string]$HexColor,
        [string]$HexRim
    )
    $size = 32
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    $fill = [System.Drawing.ColorTranslator]::FromHtml($HexColor)
    $rim = [System.Drawing.ColorTranslator]::FromHtml($HexRim)

    [float]$margin = 3.5
    [float]$rectSize = $size - (2.0 * $margin)
    $rect = New-Object System.Drawing.RectangleF -ArgumentList $margin, $margin, $rectSize, $rectSize

    $rimPen = New-Object System.Drawing.Pen -ArgumentList $rim, ([float]1.6)
    $g.DrawEllipse($rimPen, $rect)

    [float]$inset = 2.0
    [float]$innerX = $rect.X + $inset
    [float]$innerY = $rect.Y + $inset
    [float]$innerSize = $rect.Width - (2.0 * $inset)
    $innerRect = New-Object System.Drawing.RectangleF -ArgumentList $innerX, $innerY, $innerSize, $innerSize
    $brush = New-Object System.Drawing.SolidBrush -ArgumentList $fill
    $g.FillEllipse($brush, $innerRect)
    $g.Dispose()

    # Encode as PNG in memory (no palette quantization), then wrap in a
    # minimal single-frame ICO container by hand.
    $pngStream = New-Object System.IO.MemoryStream
    $bmp.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $pngStream.ToArray()
    $bmp.Dispose()

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
    $bw = New-Object System.IO.BinaryWriter($fs)

    # ICONDIR: reserved(2)=0, type(2)=1 (icon), count(2)=1
    $bw.Write([UInt16]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]1)

    # ICONDIRENTRY: width(1) height(1) colorCount(1)=0 reserved(1)=0
    # planes(2)=1 bitCount(2)=32 bytesInRes(4) imageOffset(4)=22
    $bw.Write([byte]$size)
    $bw.Write([byte]$size)
    $bw.Write([byte]0)
    $bw.Write([byte]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]32)
    $bw.Write([UInt32]$pngBytes.Length)
    $bw.Write([UInt32]22)

    $bw.Write($pngBytes)
    $bw.Flush()
    $fs.Close()

    Write-Output "wrote $Path ($($pngBytes.Length) bytes png payload)"
}

$outDir = "d:\Projects\projects_macbook\chimera_protocol\app\assets\icons"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

# Tokens from app/lib/theme.dart (dark palette -- brightest, most legible
# against both light and dark taskbars, matches the app's dark-first identity).
New-DotIcon -Path "$outDir\app_icon_connected.ico"    -HexColor "#49D6B3" -HexRim "#1C7A61"
New-DotIcon -Path "$outDir\app_icon_disconnected.ico" -HexColor "#8FA098" -HexRim "#4E5D56"
New-DotIcon -Path "$outDir\app_icon_error.ico"        -HexColor "#E2604F" -HexRim "#8E2E22"
