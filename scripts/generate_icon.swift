#!/usr/bin/env swift
import AppKit
import CoreGraphics
import Foundation

func renderIcon(size: Int) -> NSImage {
    let s = CGFloat(size)
    let img = NSImage(size: NSSize(width: s, height: s))
    img.lockFocus()
    defer { img.unlockFocus() }

    guard let ctx = NSGraphicsContext.current?.cgContext else { return img }
    ctx.setAllowsAntialiasing(true)
    ctx.setShouldAntialias(true)
    ctx.interpolationQuality = .high

    // macOS HIG squircle inset (~10% padding for standard Dock visual weight)
    let pad = s * 0.095
    let rect = CGRect(x: pad, y: pad, width: s - pad * 2, height: s - pad * 2)
    let radius = rect.width * 0.225
    let bgPath = CGPath(roundedRect: rect, cornerWidth: radius, cornerHeight: radius, transform: nil)

    // Soft outer shadow
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.025), blur: s * 0.055, color: NSColor.black.withAlphaComponent(0.28).cgColor)
    ctx.addPath(bgPath)
    ctx.setFillColor(NSColor(calibratedRed: 0.04, green: 0.36, blue: 0.38, alpha: 1).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    // Gradient fill inside squircle (rich deep ocean teal -> vibrant emerald teal)
    ctx.saveGState()
    ctx.addPath(bgPath)
    ctx.clip()

    let colorSpace = CGColorSpaceCreateDeviceRGB()
    let bgColors = [
        NSColor(calibratedRed: 0.03, green: 0.19, blue: 0.27, alpha: 1).cgColor,
        NSColor(calibratedRed: 0.04, green: 0.45, blue: 0.47, alpha: 1).cgColor,
        NSColor(calibratedRed: 0.10, green: 0.72, blue: 0.65, alpha: 1).cgColor,
    ] as CFArray
    if let grad = CGGradient(colorsSpace: colorSpace, colors: bgColors, locations: [0.0, 0.55, 1.0]) {
        ctx.drawLinearGradient(
            grad,
            start: CGPoint(x: rect.minX, y: rect.minY),
            end: CGPoint(x: rect.maxX, y: rect.maxY),
            options: []
        )
    }

    // Subtle radial top-left sheen
    let sheenColors = [
        NSColor.white.withAlphaComponent(0.22).cgColor,
        NSColor.white.withAlphaComponent(0.0).cgColor,
    ] as CFArray
    if let radial = CGGradient(colorsSpace: colorSpace, colors: sheenColors, locations: [0.0, 1.0]) {
        ctx.drawRadialGradient(
            radial,
            startCenter: CGPoint(x: rect.minX + rect.width * 0.25, y: rect.maxY - rect.height * 0.15),
            startRadius: 0,
            endCenter: CGPoint(x: rect.minX + rect.width * 0.25, y: rect.maxY - rect.height * 0.15),
            endRadius: rect.width * 0.75,
            options: []
        )
    }
    ctx.restoreGState()

    // Subtle inner specular border
    ctx.saveGState()
    ctx.addPath(bgPath)
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.24).cgColor)
    ctx.setLineWidth(max(1.0, s * 0.012))
    ctx.strokePath()
    ctx.restoreGState()

    // Central Shield silhouette (frosted translucent glass)
    let cx = s * 0.5
    let topY = s * 0.76
    let shoulderY = s * 0.68
    let midY = s * 0.44
    let botY = s * 0.21
    let halfW = s * 0.245

    let shield = CGMutablePath()
    shield.move(to: CGPoint(x: cx, y: topY))
    shield.addLine(to: CGPoint(x: cx + halfW, y: shoulderY))
    shield.addLine(to: CGPoint(x: cx + halfW, y: midY))
    shield.addCurve(
        to: CGPoint(x: cx, y: botY),
        control1: CGPoint(x: cx + halfW, y: s * 0.30),
        control2: CGPoint(x: cx + halfW * 0.45, y: s * 0.24)
    )
    shield.addCurve(
        to: CGPoint(x: cx - halfW, y: midY),
        control1: CGPoint(x: cx - halfW * 0.45, y: s * 0.24),
        control2: CGPoint(x: cx - halfW, y: s * 0.30)
    )
    shield.addLine(to: CGPoint(x: cx - halfW, y: shoulderY))
    shield.closeSubpath()

    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -s * 0.015), blur: s * 0.035, color: NSColor.black.withAlphaComponent(0.22).cgColor)
    ctx.addPath(shield)
    ctx.setFillColor(NSColor.white.withAlphaComponent(0.18).cgColor)
    ctx.fillPath()
    ctx.restoreGState()

    ctx.saveGState()
    ctx.addPath(shield)
    ctx.setStrokeColor(NSColor.white.withAlphaComponent(0.88).cgColor)
    ctx.setLineWidth(max(1.2, s * 0.028))
    ctx.setLineJoin(.round)
    ctx.strokePath()
    ctx.restoreGState()

    // Crisp ECG heartbeat waveform across shield center
    let pulse = CGMutablePath()
    let baseY = s * 0.48
    pulse.move(to: CGPoint(x: cx - halfW * 0.72, y: baseY))
    pulse.addLine(to: CGPoint(x: cx - halfW * 0.34, y: baseY))
    pulse.addLine(to: CGPoint(x: cx - halfW * 0.16, y: baseY + s * 0.115))
    pulse.addLine(to: CGPoint(x: cx + halfW * 0.04, y: baseY - s * 0.125))
    pulse.addLine(to: CGPoint(x: cx + halfW * 0.24, y: baseY + s * 0.055))
    pulse.addLine(to: CGPoint(x: cx + halfW * 0.38, y: baseY))
    pulse.addLine(to: CGPoint(x: cx + halfW * 0.72, y: baseY))

    ctx.saveGState()
    ctx.setShadow(offset: .zero, blur: s * 0.025, color: NSColor(calibratedRed: 0.45, green: 1.0, blue: 0.90, alpha: 0.75).cgColor)
    ctx.addPath(pulse)
    ctx.setStrokeColor(NSColor.white.cgColor)
    ctx.setLineWidth(max(1.4, s * 0.038))
    ctx.setLineCap(.round)
    ctx.setLineJoin(.round)
    ctx.strokePath()
    ctx.restoreGState()

    return img
}

func savePNG(_ image: NSImage, to url: URL, pixels: Int) throws {
    guard let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil,
        pixelsWide: pixels,
        pixelsHigh: pixels,
        bitsPerSample: 8,
        samplesPerPixel: 4,
        hasAlpha: true,
        isPlanar: false,
        colorSpaceName: .calibratedRGB,
        bytesPerRow: 0,
        bitsPerPixel: 0
    ) else {
        throw NSError(domain: "icon", code: 1)
    }
    rep.size = NSSize(width: pixels, height: pixels)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    image.draw(in: NSRect(x: 0, y: 0, width: pixels, height: pixels))
    NSGraphicsContext.restoreGraphicsState()
    guard let data = rep.representation(using: .png, properties: [:]) else {
        throw NSError(domain: "icon", code: 2)
    }
    try data.write(to: url)
}

func buildICO(images: [(size: Int, png: Data)]) -> Data {
    var header = Data()
    func appendU16(_ v: UInt16) {
        var le = v.littleEndian
        header.append(Data(bytes: &le, count: 2))
    }
    func appendU32(_ v: UInt32) {
        var le = v.littleEndian
        header.append(Data(bytes: &le, count: 4))
    }
    appendU16(0) // reserved
    appendU16(1) // ICO type
    appendU16(UInt16(images.count))

    var offset = UInt32(6 + images.count * 16)
    var body = Data()
    for item in images {
        let dim: UInt8 = item.size >= 256 ? 0 : UInt8(item.size)
        header.append(dim)
        header.append(dim)
        header.append(0)
        header.append(0)
        appendU16(1)  // planes
        appendU16(32) // bpp
        appendU32(UInt32(item.png.count))
        appendU32(offset)
        offset += UInt32(item.png.count)
        body.append(item.png)
    }
    header.append(body)
    return header
}

let projectDir = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
let iconsetDir = projectDir.appendingPathComponent("build/AppIcon.iconset", isDirectory: true)
try FileManager.default.createDirectory(at: iconsetDir, withIntermediateDirectories: true)

let specs: [(String, Int)] = [
    ("icon_16x16.png", 16),
    ("icon_16x16@2x.png", 32),
    ("icon_32x32.png", 32),
    ("icon_32x32@2x.png", 64),
    ("icon_128x128.png", 128),
    ("icon_128x128@2x.png", 256),
    ("icon_256x256.png", 256),
    ("icon_256x256@2x.png", 512),
    ("icon_512x512.png", 512),
    ("icon_512x512@2x.png", 1024),
]

for (name, px) in specs {
    let img = renderIcon(size: px)
    try savePNG(img, to: iconsetDir.appendingPathComponent(name), pixels: px)
}

let resourcesDir = projectDir.appendingPathComponent("Resources", isDirectory: true)
try FileManager.default.createDirectory(at: resourcesDir, withIntermediateDirectories: true)

// Also write Windows multi-res .ico (16, 32, 48, 64)
let winIcoDir = projectDir.appendingPathComponent("windows/internal/tray", isDirectory: true)
try FileManager.default.createDirectory(at: winIcoDir, withIntermediateDirectories: true)
var icoFrames: [(Int, Data)] = []
for px in [16, 32, 48, 64] {
    let tmp = iconsetDir.appendingPathComponent("win_\(px).png")
    try savePNG(renderIcon(size: px), to: tmp, pixels: px)
    icoFrames.append((px, try Data(contentsOf: tmp)))
    try? FileManager.default.removeItem(at: tmp)
}
try buildICO(images: icoFrames).write(to: winIcoDir.appendingPathComponent("app.ico"))
print("Generated iconset and Windows app.ico")
