# Draws the Pointsman icon and writes it as a multi-size .ico plus a PNG for docs.
#
# The mark is the one already in the window header: two arrows passing each
# other in opposite directions, on the blue rounded square from the palette.
# The arrows are drawn as geometry rather than set as the ⇄ character, so the
# icon does not depend on a font being present and stays crisp at every size.
#
# Kept in the repo so the icon can be regenerated rather than being a binary
# nobody can edit. Run:  powershell -ExecutionPolicy Bypass -File assets\generate-icon.ps1

Add-Type -AssemblyName System.Drawing

$ErrorActionPreference = 'Stop'
$root    = Split-Path -Parent $PSScriptRoot
$icoPath = Join-Path $root 'src\Pointsman.App\Resources\pointsman.ico'
$pngPath = Join-Path $root 'assets\pointsman.png'

# Matches Resources\Styles.xaml: AccentBrush on the square, white on the arrows.
$accent = [System.Drawing.ColorTranslator]::FromHtml('#2563EB')
$ink    = [System.Drawing.Color]::White

function New-RoundedPath([float]$x, [float]$y, [float]$w, [float]$h, [float]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x,             $y,             $d, $d, 180, 90)
    $p.AddArc($x + $w - $d,   $y,             $d, $d, 270, 90)
    $p.AddArc($x + $w - $d,   $y + $h - $d,   $d, $d,   0, 90)
    $p.AddArc($x,             $y + $h - $d,   $d, $d,  90, 90)
    $p.CloseFigure()
    return $p
}

function New-IconBitmap([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g   = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear([System.Drawing.Color]::Transparent)

    # Everything is described on a 256-unit grid and scaled, so one set of
    # coordinates serves every size. The corner radius is the same proportion
    # the header badge uses.
    $s = $size / 256.0

    $bg    = New-RoundedPath 0 0 $size $size ([float](68 * $s))
    $brush = New-Object System.Drawing.SolidBrush $accent
    $g.FillPath($brush, $bg)
    $brush.Dispose(); $bg.Dispose()

    # Below about 24px an arrowhead is a couple of pixels and turns to mush, so
    # the strokes get heavier and the heads blunter as the canvas shrinks.
    $stroke = [float]([Math]::Max(2.0, 23 * $s))
    $pen = New-Object System.Drawing.Pen($ink, $stroke)
    $pen.StartCap = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.EndCap   = [System.Drawing.Drawing2D.LineCap]::Round
    $pen.LineJoin = [System.Drawing.Drawing2D.LineJoin]::Round

    # Upper arrow, travelling right.
    $g.DrawLine($pen, [float](70*$s), [float](100*$s), [float](178*$s), [float](100*$s))
    $head = New-Object System.Drawing.Drawing2D.GraphicsPath
    $head.AddLine([float](148*$s), [float](72*$s),  [float](182*$s), [float](100*$s))
    $head.AddLine([float](182*$s), [float](100*$s), [float](148*$s), [float](128*$s))
    $g.DrawPath($pen, $head); $head.Dispose()

    # Lower arrow, travelling left. Offset from the upper one so the pair reads
    # as two routes passing rather than one double-headed arrow.
    $g.DrawLine($pen, [float](78*$s), [float](156*$s), [float](186*$s), [float](156*$s))
    $head = New-Object System.Drawing.Drawing2D.GraphicsPath
    $head.AddLine([float](108*$s), [float](128*$s), [float](74*$s),  [float](156*$s))
    $head.AddLine([float](74*$s),  [float](156*$s), [float](108*$s), [float](184*$s))
    $g.DrawPath($pen, $head); $head.Dispose()

    $pen.Dispose()
    $g.Dispose()
    return $bmp
}

function Get-PngBytes([System.Drawing.Bitmap]$bmp) {
    $ms = New-Object System.IO.MemoryStream
    $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    $bytes = $ms.ToArray()
    $ms.Dispose()
    # The comma matters: PowerShell unrolls an array on return, and a byte[] that
    # comes back as Object[] writes nothing at all through BinaryWriter — the
    # first attempt produced a 118-byte file containing only the header.
    return ,[byte[]]$bytes
}

# A 32-bit DIB as an .ico entry: BITMAPINFOHEADER with the height doubled to
# cover the AND mask, then the pixels bottom-up, then the mask itself. The mask
# is left empty because the alpha channel already carries transparency; it has
# to be present and padded to 4-byte rows all the same.
function Get-DibBytes([System.Drawing.Bitmap]$bmp) {
    $w = $bmp.Width; $h = $bmp.Height
    $rect = New-Object System.Drawing.Rectangle(0, 0, $w, $h)
    $data = $bmp.LockBits($rect, [System.Drawing.Imaging.ImageLockMode]::ReadOnly,
                          [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $pixels = New-Object byte[] ($data.Stride * $h)
    [System.Runtime.InteropServices.Marshal]::Copy($data.Scan0, $pixels, 0, $pixels.Length)
    $stride = $data.Stride
    $bmp.UnlockBits($data)

    $ms = New-Object System.IO.MemoryStream
    $bw = New-Object System.IO.BinaryWriter($ms)
    $bw.Write([UInt32]40)          # biSize
    $bw.Write([Int32]$w)           # biWidth
    $bw.Write([Int32]($h * 2))     # biHeight: image plus mask
    $bw.Write([UInt16]1)           # biPlanes
    $bw.Write([UInt16]32)          # biBitCount
    $bw.Write([UInt32]0)           # biCompression: BI_RGB
    $bw.Write([UInt32]($w * $h * 4))
    $bw.Write([Int32]0); $bw.Write([Int32]0)   # pixels-per-metre
    $bw.Write([UInt32]0); $bw.Write([UInt32]0) # palette

    # DIB rows run bottom-up.
    for ($y = $h - 1; $y -ge 0; $y--) {
        $bw.Write($pixels, $y * $stride, $w * 4)
    }

    $maskRow = [Math]::Floor((($w + 31) / 32)) * 4
    $bw.Write((New-Object byte[] ($maskRow * $h)), 0, $maskRow * $h)

    $bw.Flush()
    $bytes = $ms.ToArray()
    $bw.Dispose(); $ms.Dispose()
    return ,[byte[]]$bytes
}

$sizes  = @(16, 24, 32, 48, 64, 128, 256)
$images = @()
foreach ($size in $sizes) {
    $bmp = New-IconBitmap $size
    if ($size -eq 256) { $bmp.Save($pngPath, [System.Drawing.Imaging.ImageFormat]::Png) }

    # Only the 256 entry is PNG-compressed. GDI+ chokes on PNG entries at some
    # sizes — Icon.ToBitmap() threw "Requested range extends past the end of the
    # array" when every entry was stored that way — and at 256 the uncompressed
    # form would be 256 KB on its own, so that one is worth the risk.
    $bytes = if ($size -eq 256) { Get-PngBytes $bmp } else { Get-DibBytes $bmp }
    $images += ,@{ Size = $size; Bytes = $bytes }
    $bmp.Dispose()
}

$ms = New-Object System.IO.MemoryStream
$bw = New-Object System.IO.BinaryWriter($ms)

$bw.Write([UInt16]0)                 # reserved
$bw.Write([UInt16]1)                 # type: icon
$bw.Write([UInt16]$images.Count)

$offset = 6 + (16 * $images.Count)
foreach ($img in $images) {
    $dim = if ($img.Size -eq 256) { 0 } else { $img.Size }   # 0 means 256 in this format
    $bw.Write([Byte]$dim)            # width
    $bw.Write([Byte]$dim)            # height
    $bw.Write([Byte]0)               # palette size: none
    $bw.Write([Byte]0)               # reserved
    $bw.Write([UInt16]1)             # colour planes
    $bw.Write([UInt16]32)            # bits per pixel
    $bw.Write([UInt32]$img.Bytes.Length)
    $bw.Write([UInt32]$offset)
    $offset += $img.Bytes.Length
}
foreach ($img in $images) {
    $payload = [byte[]]$img.Bytes
    $bw.Write($payload, 0, $payload.Length)
}

$bw.Flush()
[System.IO.File]::WriteAllBytes($icoPath, $ms.ToArray())
$bw.Dispose(); $ms.Dispose()

# Read it back rather than trusting the byte count: a malformed .ico still has a
# plausible size, and the first thing that would tell us otherwise is a blank
# tile on somebody's desktop.
#
# Check with WIC, the decoder Windows itself uses for icons, and which reads
# every frame including the 256 PNG. GDI+ is checked too but only up to 128:
# its Icon class does not understand a 256px entry and silently hands back the
# 128 one, so asking it about 256 proves nothing about the file.
Add-Type -AssemblyName PresentationCore
$uri     = New-Object System.Uri($icoPath)
$decoder = New-Object System.Windows.Media.Imaging.IconBitmapDecoder(
    $uri,
    [System.Windows.Media.Imaging.BitmapCreateOptions]::PreservePixelFormat,
    [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad)

$decoded = $decoder.Frames | ForEach-Object { $_.PixelWidth } | Sort-Object -Unique
$missing = $sizes | Where-Object { $decoded -notcontains $_ }
if ($missing) { throw "Icon is missing usable frames at: $($missing -join ', ')" }

foreach ($size in ($sizes | Where-Object { $_ -le 128 })) {
    $check = New-Object System.Drawing.Icon($icoPath, $size, $size)
    # Decoding, not just selecting — this is the step that failed while the
    # entries were PNG.
    $probe = $check.ToBitmap()
    if ($probe.Width -ne $size) { throw "Entry ${size}px decoded to $($probe.Width)px" }
    $probe.Dispose(); $check.Dispose()
}

Write-Host "Wrote $icoPath ($([Math]::Round((Get-Item $icoPath).Length / 1KB, 1)) KB, sizes: $($sizes -join ', '))"
Write-Host "Wrote $pngPath"
