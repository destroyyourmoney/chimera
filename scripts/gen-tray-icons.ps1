# Regenerates app_icon.ico (chimera_tray.exe's own icon) and the three
# tray-state icons (connected/disconnected/error) from the single master
# mark at app/assets/icons/source/chimera_mark.png -- a white silhouette on
# a solid dark background (see that file's own generation prompt in
# ROADMAP.md/commit history if it ever needs regenerating from scratch).
#
# The tray-state icons are NOT flat dots anymore: each is the same chimera
# silhouette recolored per connection state, with alpha derived from the
# source's luminance (background -> transparent, white shape -> opaque),
# so they composite cleanly onto any taskbar color. Run this after changing
# tray state colors or replacing the source mark; output lands in
# app/assets/icons/ (bundled as a Flutter asset, resolved at runtime
# relative to the executable) and app/windows/runner/resources/app_icon.ico
# (the exe/taskbar icon, embedded into chimera_tray.exe at build time).
Add-Type -AssemblyName System.Drawing

$repoRoot = "d:\Projects\projects_macbook\chimera_protocol"
$sourcePath = "$repoRoot\app\assets\icons\source\chimera_mark.png"

# Sampled from the source art: background ~(35,33,34), lion shape ~(253,253,251).
# Luminance between these two anchors is remapped to alpha 0..255, which
# also preserves the source's antialiasing at the shape's edges instead of a
# hard-edged cutout.
$bgLum = 34.0
$fgLum = 253.0

# Recolors $src (loaded once, kept in ARGB32) into a same-size bitmap where
# RGB = $HexColor and alpha comes from source luminance as described above.
function ConvertTo-ColoredMask {
    param(
        [System.Drawing.Bitmap]$Src,
        [string]$HexColor
    )
    $color = [System.Drawing.ColorTranslator]::FromHtml($HexColor)
    $w = $Src.Width
    $h = $Src.Height
    $out = New-Object System.Drawing.Bitmap $w, $h, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)

    $srcData = $Src.LockBits(
        (New-Object System.Drawing.Rectangle 0, 0, $w, $h),
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $outData = $out.LockBits(
        (New-Object System.Drawing.Rectangle 0, 0, $w, $h),
        [System.Drawing.Imaging.ImageLockMode]::WriteOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)

    $stride = $srcData.Stride
    $bytes = $stride * $h
    $srcBuf = New-Object byte[] $bytes
    [System.Runtime.InteropServices.Marshal]::Copy($srcData.Scan0, $srcBuf, 0, $bytes)
    $outBuf = New-Object byte[] $bytes

    $range = $fgLum - $bgLum
    for ($i = 0; $i -lt $bytes; $i += 4) {
        # BGRA byte order in memory for Format32bppArgb.
        $b = $srcBuf[$i]; $g = $srcBuf[$i + 1]; $r = $srcBuf[$i + 2]
        $lum = ($r + $g + $b) / 3.0
        $a = [Math]::Round((($lum - $bgLum) / $range) * 255.0)
        if ($a -lt 0) { $a = 0 }; if ($a -gt 255) { $a = 255 }
        $outBuf[$i]     = $color.B
        $outBuf[$i + 1] = $color.G
        $outBuf[$i + 2] = $color.R
        $outBuf[$i + 3] = [byte]$a
    }

    [System.Runtime.InteropServices.Marshal]::Copy($outBuf, 0, $outData.Scan0, $bytes)
    $Src.UnlockBits($srcData)
    $out.UnlockBits($outData)
    return $out
}

# High-quality downscale with premultiplied alpha (avoids the dark halo you
# get resizing straight ARGB with transparent-black backgrounds).
function Resize-Bitmap {
    param([System.Drawing.Bitmap]$Src, [int]$Size)
    $dst = New-Object System.Drawing.Bitmap $Size, $Size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($dst)
    $g.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
    $g.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $g.DrawImage($Src, (New-Object System.Drawing.Rectangle 0, 0, $Size, $Size))
    $g.Dispose()
    return $dst
}

# Finds the tight bounding box of the non-background silhouette and returns
# a centered square crop of $Src padded by $PaddingFrac of the box's larger
# dimension. The source mark has a lot of empty margin around the lion (by
# design, for a comfortable app-icon composition) -- at 16-32px tray sizes
# that margin ate most of the icon's visible pixels, which is why the tray
# icon looked "too small" even though the file itself was fine. Cropping
# tight before the recolor+downscale pipeline makes the glyph fill the
# canvas instead. Bbox detection runs on a small downscaled copy for speed
# (the source is 2048px) and is scaled back up to source-pixel coordinates.
function Get-TightSquareCrop {
    param([System.Drawing.Bitmap]$Src, [double]$PaddingFrac = 0.08)
    $probeSize = 256
    $probe = Resize-Bitmap -Src $Src -Size $probeSize
    $data = $probe.LockBits(
        (New-Object System.Drawing.Rectangle 0, 0, $probeSize, $probeSize),
        [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $bytes = $data.Stride * $probeSize
    $buf = New-Object byte[] $bytes
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $buf, 0, $bytes)
    $probe.UnlockBits($data)

    $minX = $probeSize; $minY = $probeSize; $maxX = 0; $maxY = 0
    $range = $fgLum - $bgLum
    for ($y = 0; $y -lt $probeSize; $y++) {
        $row = $y * $data.Stride
        for ($x = 0; $x -lt $probeSize; $x++) {
            $i = $row + ($x * 4)
            $lum = ($buf[$i + 2] + $buf[$i + 1] + $buf[$i]) / 3.0
            $a = (($lum - $bgLum) / $range) * 255.0
            if ($a -gt 40) {
                if ($x -lt $minX) { $minX = $x }
                if ($x -gt $maxX) { $maxX = $x }
                if ($y -lt $minY) { $minY = $y }
                if ($y -gt $maxY) { $maxY = $y }
            }
        }
    }

    $scale = $Src.Width / [double]$probeSize
    $bx0 = $minX * $scale; $by0 = $minY * $scale
    $bx1 = ($maxX + 1) * $scale; $by1 = ($maxY + 1) * $scale
    $bw = $bx1 - $bx0; $bh = $by1 - $by0
    $cx = ($bx0 + $bx1) / 2.0; $cy = ($by0 + $by1) / 2.0

    $side = [Math]::Max($bw, $bh) * (1.0 + 2.0 * $PaddingFrac)
    $half = $side / 2.0
    $left = [Math]::Max(0, [Math]::Round($cx - $half))
    $top = [Math]::Max(0, [Math]::Round($cy - $half))
    $edge = [Math]::Min($Src.Width - $left, $Src.Height - $top)
    $edge = [Math]::Min($edge, [Math]::Round($side))

    return $Src.Clone(
        (New-Object System.Drawing.Rectangle $left, $top, $edge, $edge),
        [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
}

# Draws a small filled circle badge (fill + darker rim) centered on $bmp,
# in place -- used for the error icon's red center dot on the green mark.
function Add-CenterDot {
    param([System.Drawing.Bitmap]$Bmp, [string]$HexFill, [string]$HexRim)
    $size = $Bmp.Width
    $g = [System.Drawing.Graphics]::FromImage($Bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $fill = [System.Drawing.ColorTranslator]::FromHtml($HexFill)
    $rim = [System.Drawing.ColorTranslator]::FromHtml($HexRim)
    [float]$r = $size * 0.115
    [float]$cx = $size / 2.0
    [float]$cy = $size / 2.0
    $rect = New-Object System.Drawing.RectangleF ($cx - $r), ($cy - $r), (2 * $r), (2 * $r)
    $brush = New-Object System.Drawing.SolidBrush -ArgumentList $fill
    $g.FillEllipse($brush, $rect)
    $pen = New-Object System.Drawing.Pen -ArgumentList $rim, ([float]($size * 0.025))
    $g.DrawEllipse($pen, $rect)
    $g.Dispose()
}

# Packs one or more same-format bitmaps (each PNG-compressed) into a single
# multi-entry ICO container (valid on Vista+). Avoids Bitmap.GetHicon(),
# which routes through legacy GDI and quantizes true-color ARGB down to a
# reduced system palette.
function Write-Ico {
    param([string]$Path, [System.Drawing.Bitmap[]]$Bitmaps)
    $pngs = @()
    foreach ($b in $Bitmaps) {
        $ms = New-Object System.IO.MemoryStream
        $b.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        $pngs += ,$ms.ToArray()
    }

    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Create)
    $bw = New-Object System.IO.BinaryWriter($fs)

    $bw.Write([UInt16]0)
    $bw.Write([UInt16]1)
    $bw.Write([UInt16]$Bitmaps.Count)

    $offset = 6 + (16 * $Bitmaps.Count)
    for ($i = 0; $i -lt $Bitmaps.Count; $i++) {
        $s = $Bitmaps[$i].Width
        $sizeByte = if ($s -ge 256) { 0 } else { [byte]$s }
        $bw.Write([byte]$sizeByte)
        $bw.Write([byte]$sizeByte)
        $bw.Write([byte]0)
        $bw.Write([byte]0)
        $bw.Write([UInt16]1)
        $bw.Write([UInt16]32)
        $bw.Write([UInt32]$pngs[$i].Length)
        $bw.Write([UInt32]$offset)
        $offset += $pngs[$i].Length
    }
    foreach ($p in $pngs) { $bw.Write($p) }
    $bw.Flush()
    $fs.Close()
    Write-Output "wrote $Path ($($Bitmaps.Count) size(s))"
}

$source = New-Object System.Drawing.Bitmap $sourcePath

# -- app_icon.ico: chimera_tray.exe's own icon -- the static brand mark, not
# state-dependent, so it's just the source packed at standard Windows sizes.
$appSizes = 16, 32, 48, 256
$appBitmaps = $appSizes | ForEach-Object { Resize-Bitmap -Src $source -Size $_ }
Write-Ico -Path "$repoRoot\app\windows\runner\resources\app_icon.ico" -Bitmaps $appBitmaps

# -- Tray-state icons: same mark, tightly cropped to fill the canvas (see
# Get-TightSquareCrop) and recolored. Windows requests different frame sizes
# from the tray icon depending on display scaling (16px at 100%, up to 32px
# at 200%); shipping all four instead of a single 32x32 frame means it
# always gets a crisp native-resolution frame instead of scaling one up/down.
$outDir = "$repoRoot\app\assets\icons"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$traySizes = 16, 20, 24, 32

$trayCrop = Get-TightSquareCrop -Src $source

# Colors mirror app/lib/theme.dart's dark palette: _darkDanger (#E2604F) and
# _darkAccent (#49D6B3) -- so the tray matches the in-app connect/error colors
# instead of introducing a second, unrelated red/green.
$disconnectedMask = ConvertTo-ColoredMask -Src $trayCrop -HexColor "#E2604F"
$connectedMask    = ConvertTo-ColoredMask -Src $trayCrop -HexColor "#49D6B3"
$errorMask        = ConvertTo-ColoredMask -Src $trayCrop -HexColor "#49D6B3"

$disconnectedBitmaps = $traySizes | ForEach-Object { Resize-Bitmap -Src $disconnectedMask -Size $_ }
$connectedBitmaps    = $traySizes | ForEach-Object { Resize-Bitmap -Src $connectedMask -Size $_ }
$errorBitmaps        = $traySizes | ForEach-Object {
    $b = Resize-Bitmap -Src $errorMask -Size $_
    Add-CenterDot -Bmp $b -HexFill "#E2604F" -HexRim "#8E2E22"
    $b
}

Write-Ico -Path "$outDir\app_icon_disconnected.ico" -Bitmaps $disconnectedBitmaps
Write-Ico -Path "$outDir\app_icon_connected.ico" -Bitmaps $connectedBitmaps
Write-Ico -Path "$outDir\app_icon_error.ico" -Bitmaps $errorBitmaps

$source.Dispose()
