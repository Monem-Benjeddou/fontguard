// Fontguard: window + menu-bar front end for fontguard.py.
// The app owns the watcher process, so macOS privacy (TCC) charges file access to this
// app: granting Full Disk Access to Fontguard.app covers Downloads/Desktop/Documents
// without giving every python3 script that access.
import AppKit
import ServiceManagement
import SwiftUI
import UniformTypeIdentifiers

let home = FileManager.default.homeDirectoryForCurrentUser.path
// build.sh records the install folder in Info.plist (FGHome); ~/.fontguard otherwise.
let fgHome: String = {
    if let h = Bundle.main.object(forInfoDictionaryKey: "FGHome") as? String, !h.isEmpty { return h }
    return home + "/.fontguard"
}()
let script = fgHome + "/fontguard.py"
let quarantineDir = fgHome + "/quarantine"
let logPath = fgHome + "/fontguard.log"
let statusPath = fgHome + "/status.json"
let python = FileManager.default.isExecutableFile(atPath: "/usr/bin/python3") ? "/usr/bin/python3" : "/opt/homebrew/bin/python3"
// The login agent lives inside the bundle (build.sh writes it) and is registered with SMAppService,
// so it shows up under System Settings > General > Login Items like any other app.
let agentPlist = "com.fontguard.agent.plist"
let logQueue = DispatchQueue(label: "fontguard.log")

// MARK: - Models

struct Finding: Identifiable {
    let id = UUID()
    let date: Date?
    let path: String
    let reason: String
    let dest: String?
}

/// One quarantine event: a timestamped folder holding everything moved at that moment.
struct Incident: Identifiable {
    var id: String { folder }
    let folder: String
    let date: Date?
    let source: String
    let files: [String]  // paths relative to the incident's source folder
    let size: Int64
    var restorable: Bool { source == "watch" || source == "scan" }
}

struct LogEntry: Identifiable {
    enum Kind { case caught, blocked, info }
    let id = UUID()
    let date: Date?
    let kind: Kind
    let text: String
}

enum Pane: Hashable { case overview, scan, quarantine, activity }

/// Parses "🚨 [fontguard] PATH: REASON", "... -> moved to DEST" or "... -> stopped".
func parse(_ line: String, date: Date?) -> Finding? {
    guard let tag = line.range(of: "[fontguard] ") else { return nil }
    var body = String(line[tag.upperBound...])
    var dest: String?
    if let arrow = body.range(of: " -> ") {
        let tail = String(body[arrow.upperBound...])
        dest = tail.hasPrefix("moved to ") ? String(tail.dropFirst("moved to ".count)) : nil
        body = String(body[..<arrow.lowerBound])
    }
    if let sep = body.range(of: ": ", options: .backwards) {
        return Finding(date: date, path: String(body[..<sep.lowerBound]), reason: String(body[sep.upperBound...]), dest: dest)
    }
    return Finding(date: date, path: body, reason: "", dest: dest)
}

func appendLog(_ text: String) {
    let stamp = ISO8601DateFormatter().string(from: Date())
    let lines = text.split(separator: "\n").map { "\(stamp)\t\($0)\n" }.joined()
    logQueue.sync {  // one writer: the watcher's output thread and scans must never interleave a line
        if !FileManager.default.fileExists(atPath: logPath) { FileManager.default.createFile(atPath: logPath, contents: nil) }
        if let h = FileHandle(forWritingAtPath: logPath) { h.seekToEndOfFile(); h.write(Data(lines.utf8)); h.closeFile() }
    }
}

func describe(_ status: SMAppService.Status) -> String {
    switch status {
    case .enabled: return "enabled"
    case .requiresApproval: return "requiresApproval"
    case .notRegistered: return "notRegistered"
    case .notFound: return "notFound"
    @unknown default: return "unknown"
    }
}

/// `Fontguard --register-login` / `--unregister-login`: used by install.sh and uninstall.sh. Prints the
/// resulting status and exits, so the installer never has to guess at launchd labels or plist paths.
func handleLoginFlags() {
    let args = CommandLine.arguments
    let register = args.contains("--register-login")
    guard register || args.contains("--unregister-login") else { return }
    let service = SMAppService.agent(plistName: agentPlist)
    do {
        if register { try service.register() } else { try service.unregister() }
    } catch {
        FileHandle.standardError.write(Data("\(error.localizedDescription)\n".utf8))
    }
    print(describe(service.status))
    exit(register ? (service.status == .enabled ? 0 : 1) : 0)
}

/// A second copy (opened from Finder while the login agent runs) hands over to the first and leaves.
func yieldToRunningInstance() {
    let me = ProcessInfo.processInfo.processIdentifier
    let others = NSRunningApplication.runningApplications(withBundleIdentifier: Bundle.main.bundleIdentifier ?? "")
        .filter { $0.processIdentifier != me }
    guard let other = others.first else { return }
    let done = DispatchSemaphore(value: 0)
    // Opening an already-running app sends it a reopen event, which shows its window.
    NSWorkspace.shared.openApplication(at: other.bundleURL ?? Bundle.main.bundleURL, configuration: .init()) { _, _ in done.signal() }
    _ = done.wait(timeout: .now() + 3)
    exit(0)
}

/// The last `limit` bytes of the log: activity never needs the whole history.
func readLogTail(limit: UInt64 = 256 * 1024) -> String {
    guard let h = FileHandle(forReadingAtPath: logPath) else { return "" }
    defer { h.closeFile() }
    let end = h.seekToEndOfFile()
    h.seek(toFileOffset: end > limit ? end - limit : 0)
    let text = String(decoding: h.readDataToEndOfFile(), as: UTF8.self)
    return end > limit ? String(text.drop { $0 != "\n" }.dropFirst()) : text
}

func run(_ args: [String]) -> (status: Int32, output: String) {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: python)
    p.arguments = [script] + args
    let pipe = Pipe()
    p.standardError = pipe
    p.standardOutput = pipe
    do { try p.run() } catch { return (-1, "could not start python3: \(error.localizedDescription)") }
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    p.waitUntilExit()
    return (p.terminationStatus, String(decoding: data, as: UTF8.self))
}

func loadIncidents() -> [Incident] {
    let fm = FileManager.default
    let stamp = DateFormatter()
    stamp.dateFormat = "yyyyMMdd-HHmmss"
    guard let folders = try? fm.contentsOfDirectory(atPath: quarantineDir) else { return [] }
    var out: [Incident] = []
    for folder in folders where !folder.hasPrefix(".") {
        let root = URL(fileURLWithPath: quarantineDir).appendingPathComponent(folder)
        guard let walker = fm.enumerator(at: root, includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey]) else { continue }
        var files: [String] = []
        var size: Int64 = 0
        var source = "manual"
        for case let url as URL in walker {
            let v = try? url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
            guard v?.isRegularFile == true, url.lastPathComponent != ".DS_Store" else { continue }
            let rel = String(url.path.dropFirst(root.path.count + 1))
            let comps = rel.split(separator: "/", maxSplits: 1).map(String.init)
            if comps.count == 2 && ["watch", "scan"].contains(comps[0]) {
                source = comps[0]
                files.append(comps[1])
            } else if comps.count == 2 && !comps[0].hasPrefix(".") {
                source = comps[0]  // git hook catches are labelled with the repo name
                files.append(comps[1])
            } else {
                files.append(rel)
            }
            size += Int64(v?.fileSize ?? 0)
        }
        if files.isEmpty { continue }
        out.append(Incident(folder: folder, date: stamp.date(from: String(folder.prefix(15))), source: source, files: files.sorted(), size: size))
    }
    return out.sorted { ($0.date ?? .distantPast) > ($1.date ?? .distantPast) }
}

// MARK: - State

@MainActor final class Guard: ObservableObject {
    static let shared = Guard()

    @Published var pane: Pane = .overview
    @Published var running = false
    @Published var paused = false
    @Published var fullDiskAccess = false
    @Published var blockedReads = 0
    @Published var activity: [LogEntry] = []
    @Published var incidents: [Incident] = []
    @Published var scanResults: [Finding] = []
    @Published var scanFolder: String?
    @Published var scanning = false
    @Published var scanMessage = ""
    @Published var selftest = ""
    @Published var loginStatus: SMAppService.Status = .notRegistered
    var openMain: (() -> Void)?
    private var watcher: Process?
    private var reloadPending = false

    init() {
        handleLoginFlags()
        yieldToRunningInstance()
        // Once per launch: a watcher orphaned by a crashed earlier instance. Restarts only touch our own.
        _ = try? Process.run(URL(fileURLWithPath: "/usr/bin/pkill"), arguments: ["-f", "fontguard.py watch"]).waitUntilExit()
        refreshAccess()
        refreshLoginStatus()
        if loginStatus == .notRegistered { enableLogin() }
        reload()
        start()
        NotificationCenter.default.addObserver(forName: NSApplication.didBecomeActiveNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated {
                Guard.shared.refreshAccess()
                Guard.shared.refreshLoginStatus()
            }
        }
    }

    // MARK: watcher

    func start() {
        watcher?.terminate()  // our own previous child only; its handler sees it is no longer current and ignores it
        let p = Process()
        p.executableURL = URL(fileURLWithPath: python)
        p.arguments = [script, "watch"]
        let pipe = Pipe()
        p.standardError = pipe
        pipe.fileHandleForReading.readabilityHandler = { h in
            let data = h.availableData
            guard !data.isEmpty else {
                h.readabilityHandler = nil  // EOF: left set, Foundation calls back in a tight loop forever
                return
            }
            let text = String(decoding: data, as: UTF8.self)
            appendLog(text)
            Task { @MainActor in Guard.shared.ingest(text) }
        }
        p.terminationHandler = { proc in
            Task { @MainActor in
                let g = Guard.shared
                guard proc === g.watcher else { return }  // a watcher we replaced on purpose
                g.running = false
                g.writeStatus()
                if !g.paused {  // crashed: come back, but never spin
                    DispatchQueue.main.asyncAfter(deadline: .now() + 10) { if !g.paused && !g.running { g.start() } }
                }
            }
        }
        do {
            try p.run()
            watcher = p
            running = true
            paused = false
        } catch {
            running = false
        }
        writeStatus()
    }

    func pause() {
        paused = true
        watcher?.terminate()
    }

    func shutdown() {
        paused = true
        watcher?.terminate()
    }

    func ingest(_ text: String) {
        if text.contains("could not check") && text.contains("not permitted") { blockedReads += 1 }
        guard text.contains("[fontguard]") || text.hasPrefix("fontguard:") else { return }
        scheduleReload()
    }

    /// Bursts (an npm install, a git clone) produce many lines: reload once, a second later.
    func scheduleReload() {
        guard !reloadPending else { return }
        reloadPending = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            let g = Guard.shared
            g.reloadPending = false
            g.reload()
        }
    }

    // MARK: data

    func reload() {
        Task.detached(priority: .utility) {
            let text = readLogTail()
            let incidents = loadIncidents()
            let iso = ISO8601DateFormatter()
            var entries: [LogEntry] = []
            for raw in text.split(separator: "\n") {
                let parts = raw.split(separator: "\t", maxSplits: 1).map(String.init)
                let (date, line) = parts.count == 2 ? (iso.date(from: parts[0]), parts[1]) : (nil, parts[0])
                guard line.contains("[fontguard]") || line.hasPrefix("fontguard:") else { continue }
                let kind: LogEntry.Kind = line.contains(" -> ") ? .caught : line.contains("could not check") ? .blocked : .info
                entries.append(LogEntry(date: date, kind: kind, text: line))
            }
            let newest = Array(entries.suffix(400).reversed())
            await MainActor.run {
                Guard.shared.activity = newest
                Guard.shared.incidents = incidents
            }
        }
    }

    var catches: [LogEntry] { activity.filter { $0.kind == .caught } }
    var quarantinedFiles: Int { incidents.reduce(0) { $0 + $1.files.count } }

    var hooksInstalled: Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/git")
        p.arguments = ["config", "--global", "core.hooksPath"]
        let pipe = Pipe()
        p.standardOutput = pipe
        try? p.run()
        p.waitUntilExit()
        let dir = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return !dir.isEmpty && ["pre-commit", "pre-push", "post-checkout"].allSatisfy {
            ((try? String(contentsOfFile: (dir as NSString).expandingTildeInPath + "/" + $0, encoding: .utf8)) ?? "").contains("fontguard")
        }
    }

    // MARK: login item

    func refreshLoginStatus() {
        loginStatus = SMAppService.agent(plistName: agentPlist).status
    }

    func enableLogin() {
        try? SMAppService.agent(plistName: agentPlist).register()
        refreshLoginStatus()
        if loginStatus == .requiresApproval { SMAppService.openSystemSettingsLoginItems() }
    }

    var loginText: String {
        switch loginStatus {
        case .enabled: return "Starts at login (System Settings › Login Items › Fontguard)"
        case .requiresApproval: return "Starts at login once you allow Fontguard in Login Items"
        case .notFound: return "Login item missing from the app bundle: rebuild with install.sh"
        default: return "Doesn't start at login yet"
        }
    }

    // MARK: access

    func refreshAccess() {
        // Reading the TCC database is the standard probe: only Full Disk Access allows it.
        if let h = FileHandle(forReadingAtPath: home + "/Library/Application Support/com.apple.TCC/TCC.db") {
            h.closeFile()
            fullDiskAccess = true
            blockedReads = 0
        } else {
            fullDiskAccess = false
        }
        writeStatus()
    }

    /// Read by setup-permissions.sh to confirm the grant took effect.
    func writeStatus() {
        let json = "{\"fullDiskAccess\": \(fullDiskAccess), \"watcher\": \(running), \"updated\": \"\(ISO8601DateFormatter().string(from: Date()))\"}\n"
        try? json.write(toFile: statusPath, atomically: true, encoding: .utf8)
    }

    func openFullDiskAccessSettings() {
        NSWorkspace.shared.open(URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles")!)
        NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL])  // ready to drag into the list
    }

    // MARK: actions

    func pickAndScan() {
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "Scan"
        panel.message = "Choose a folder to check for the git-worm malware"
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK, let url = panel.url else { return }
        scan(url.path, quarantine: false)
    }

    func scan(_ folder: String, quarantine move: Bool) {
        pane = .scan
        scanFolder = folder
        scanning = true
        scanMessage = move ? "Moving to quarantine…" : "Scanning \((folder as NSString).lastPathComponent)…"
        Task.detached {
            let result = run(["scan"] + (move ? ["--quarantine"] : []) + [folder])
            let hits = result.output.split(separator: "\n").map(String.init)
                .filter { $0.contains("🚨") }.compactMap { parse($0, date: nil) }
            await MainActor.run {
                let g = Guard.shared
                g.scanning = false
                if move {
                    appendLog(result.output)
                    g.scanResults = []
                    g.scanMessage = "Moved \(hits.count) file(s) to quarantine."
                    g.reload()
                } else {
                    g.scanResults = hits
                    g.scanMessage = hits.isEmpty ? "Clean. Nothing suspicious found." : "\(hits.count) infected file(s) found."
                }
            }
        }
    }

    func runSelftest() {
        selftest = "Running…"
        Task.detached {
            let r = run(["selftest"])
            await MainActor.run { Guard.shared.selftest = r.status == 0 ? "Passed" : "FAILED" }
        }
    }

    func reveal(_ path: String) {
        let target = FileManager.default.fileExists(atPath: path) ? path : quarantineDir
        NSWorkspace.shared.selectFile(target, inFileViewerRootedAtPath: "")
    }

    func openQuarantineFolder() {
        try? FileManager.default.createDirectory(atPath: quarantineDir, withIntermediateDirectories: true)
        NSWorkspace.shared.open(URL(fileURLWithPath: quarantineDir))
    }

    /// Moves an incident's files back to where they were. Only real-time and scan catches
    /// record their original location (fontguard.py stores it relative to /).
    func restore(_ incident: Incident) -> String? {
        guard incident.restorable else { return "The original location is unknown for this incident." }
        let fm = FileManager.default
        let base = quarantineDir + "/" + incident.folder + "/" + incident.source
        for rel in incident.files {
            let original = "/" + rel
            if fm.fileExists(atPath: original) { return "A file already exists at \(original)." }
            do {
                try fm.createDirectory(atPath: (original as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                try fm.moveItem(atPath: base + "/" + rel, toPath: original)
            } catch {
                return error.localizedDescription
            }
        }
        try? fm.removeItem(atPath: quarantineDir + "/" + incident.folder)
        reload()
        return nil
    }

    func delete(_ incidents: [Incident]) {
        for i in incidents { try? FileManager.default.removeItem(atPath: quarantineDir + "/" + i.folder) }
        reload()
    }

    // MARK: status

    var icon: String {
        if paused { return "shield.slash.fill" }
        if !running { return "xmark.shield.fill" }
        return fullDiskAccess ? "checkmark.shield.fill" : "exclamationmark.shield.fill"
    }
    var color: Color {
        if paused { return .orange }
        if !running { return .red }
        return fullDiskAccess ? .green : .yellow
    }
    var title: String {
        if paused { return "Protection paused" }
        if !running { return "Not running" }
        return fullDiskAccess ? "You're protected" : "Partly protected"
    }
    var subtitle: String {
        if paused { return "New files are not being checked. Turn protection back on when you're done." }
        if !running { return "The watcher stopped. It restarts on its own in a few seconds." }
        return fullDiskAccess
            ? "Every file that lands in your home folder is checked the moment it appears."
            : "Downloads, Desktop and Documents aren't covered until you grant Full Disk Access."
    }
}

// MARK: - Shared pieces

struct Card<Content: View>: View {
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 12) { content }
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(.background.secondary))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(.separator.opacity(0.6)))
    }
}

struct StatTile: View {
    let value: String
    let label: String
    let symbol: String
    let tint: Color
    var body: some View {
        Card {
            Image(systemName: symbol).font(.title3).foregroundStyle(tint)
            Text(value).font(.system(size: 26, weight: .semibold, design: .rounded)).lineLimit(1).minimumScaleFactor(0.6)
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
    }
}

struct FindingRow: View {
    let name: String
    let detail: String
    let date: Date?
    let action: () -> Void
    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "ladybug.fill").foregroundStyle(.red).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.callout.weight(.medium)).lineLimit(1)
                Text(detail).font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            if let date { Text(date, format: .relative(presentation: .named)).font(.caption).foregroundStyle(.tertiary) }
            Button(action: action) { Image(systemName: "magnifyingglass") }
                .buttonStyle(.borderless).help("Show in Finder")
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Overview

struct OverviewView: View {
    @EnvironmentObject var g: Guard
    @State private var hooks = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                hero
                if !g.fullDiskAccess && !g.paused { accessBanner }
                LazyVGrid(columns: Array(repeating: GridItem(.flexible(), spacing: 12), count: 4), spacing: 12) {
                    StatTile(value: "\(g.catches.count)", label: "Threats stopped", symbol: "ladybug.fill", tint: .red)
                    StatTile(value: "\(g.incidents.count)", label: "Quarantine incidents", symbol: "archivebox.fill", tint: .blue)
                    StatTile(value: lastCatch, label: "Last catch", symbol: "clock.fill", tint: .purple)
                    StatTile(value: g.running ? "Live" : "Off", label: "Real-time watcher", symbol: "waveform.path.ecg", tint: g.running ? .green : .orange)
                }
                HStack(alignment: .top, spacing: 16) {
                    coverage
                    recent
                }
            }
            .padding(24)
        }
        .navigationTitle("Overview")
        .task { hooks = g.hooksInstalled; g.refreshLoginStatus() }
    }

    var lastCatch: String {
        guard let d = g.catches.first?.date else { return "Never" }
        let f = RelativeDateTimeFormatter()
        f.unitsStyle = .short
        return f.localizedString(for: d, relativeTo: Date())
    }

    var hero: some View {
        HStack(spacing: 20) {
            ZStack {
                Circle().fill(LinearGradient(colors: [g.color.opacity(0.95), g.color.opacity(0.55)], startPoint: .top, endPoint: .bottom))
                Image(systemName: g.icon).font(.system(size: 38, weight: .semibold)).foregroundStyle(.white)
            }
            .frame(width: 84, height: 84)
            .shadow(color: g.color.opacity(0.35), radius: 12, y: 4)
            VStack(alignment: .leading, spacing: 6) {
                Text(g.title).font(.system(size: 26, weight: .bold, design: .rounded))
                Text(g.subtitle).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 8) {
                Toggle("Real-time protection", isOn: Binding(get: { !g.paused }, set: { $0 ? g.start() : g.pause() }))
                    .toggleStyle(.switch)
                Button { g.pickAndScan() } label: { Label("Scan a Folder…", systemImage: "magnifyingglass") }
                    .controlSize(.large)
            }
        }
        .padding(20)
        .background(RoundedRectangle(cornerRadius: 18, style: .continuous).fill(g.color.opacity(0.08)))
        .overlay(RoundedRectangle(cornerRadius: 18, style: .continuous).strokeBorder(g.color.opacity(0.25)))
    }

    var accessBanner: some View {
        HStack(spacing: 12) {
            Image(systemName: "lock.shield").font(.title2).foregroundStyle(.yellow)
            VStack(alignment: .leading, spacing: 2) {
                Text("Grant Full Disk Access").font(.headline)
                Text(g.blockedReads > 0
                     ? "\(g.blockedReads) file(s) couldn't be checked. Drag Fontguard into the list in Settings, switch it on, then reopen Fontguard."
                     : "Lets Fontguard check Downloads, Desktop and Documents. Drag it into the list in Settings, switch it on, then reopen it.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Open Settings…") { g.openFullDiskAccessSettings() }
            Button("Re-check") { g.refreshAccess() }
        }
        .padding(14)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(Color.yellow.opacity(0.12)))
    }

    var coverage: some View {
        Card {
            Text("What's covered").font(.headline)
            ForEach([
                ("Fake font files run by hidden VS Code tasks", "textformat"),
                ("Payloads hidden in config files (eslint, vite, postcss, tailwind…)", "curlybraces"),
                ("Workspace settings that switch auto-run back on", "gearshape"),
                ("The ~/.node_modules loader", "bolt.slash"),
                ("Known command servers and campaign markers", "network"),
            ], id: \.0) { item in
                Label { Text(item.0).font(.callout) } icon: { Image(systemName: item.1).foregroundStyle(.green) }
            }
            Divider()
            statusLine(hooks, "Git hooks: block infected commits and pushes, quarantine on clone and pull")
            HStack {
                statusLine(g.loginStatus == .enabled, g.loginText)
                if g.loginStatus != .enabled && g.loginStatus != .notFound {
                    Button(g.loginStatus == .requiresApproval ? "Open Login Items…" : "Enable") { g.enableLogin() }
                        .controlSize(.small)
                }
            }
            statusLine(g.fullDiskAccess, "Full Disk Access")
            HStack {
                Button("Run Self-test") { g.runSelftest() }
                Text(g.selftest).font(.caption).foregroundStyle(g.selftest == "FAILED" ? .red : .secondary)
            }
        }
    }

    func statusLine(_ ok: Bool, _ text: String) -> some View {
        Label { Text(text).font(.callout) } icon: {
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill").foregroundStyle(ok ? .green : .orange)
        }
    }

    var recent: some View {
        Card {
            HStack {
                Text("Recent catches").font(.headline)
                Spacer()
                Button("See all") { g.pane = .activity }.buttonStyle(.link)
            }
            if g.catches.isEmpty {
                ContentUnavailableView("Nothing caught yet", systemImage: "checkmark.shield",
                                       description: Text("Threats Fontguard blocks will show up here."))
                    .frame(maxWidth: .infinity, minHeight: 160)
            } else {
                ForEach(g.catches.prefix(6)) { e in
                    let f = parse(e.text, date: e.date)
                    FindingRow(name: ((f?.path ?? e.text) as NSString).lastPathComponent,
                               detail: f?.reason ?? "", date: e.date) { g.reveal(f?.dest ?? quarantineDir) }
                }
            }
        }
    }
}

// MARK: - Scan

struct ScanView: View {
    @EnvironmentObject var g: Guard
    @State private var targeted = false

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(spacing: 12) {
                Image(systemName: targeted ? "folder.fill.badge.plus" : "folder.badge.questionmark")
                    .font(.system(size: 44)).foregroundStyle(targeted ? Color.accentColor : .secondary)
                Text("Drop a folder here to scan it").font(.title3.weight(.semibold))
                Text("Repos, downloads, unzipped projects. Nothing changes until you choose to quarantine. Apps and system folders are skipped.")
                    .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                Button { g.pickAndScan() } label: { Label("Choose Folder…", systemImage: "folder") }
                    .controlSize(.large).buttonStyle(.borderedProminent)
            }
            .padding(.horizontal, 24)
            .frame(maxWidth: .infinity, minHeight: 220)
            .background(RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
                .foregroundStyle(targeted ? Color.accentColor : Color.secondary.opacity(0.4)))
            .onDrop(of: [.fileURL], isTargeted: $targeted) { providers in
                _ = providers.first?.loadObject(ofClass: URL.self) { url, _ in
                    if let url { Task { @MainActor in Guard.shared.scan(url.path, quarantine: false) } }
                }
                return true
            }

            if g.scanning || !g.scanMessage.isEmpty {
                Card {
                    HStack(spacing: 10) {
                        if g.scanning {
                            ProgressView().controlSize(.small)
                        } else {
                            Image(systemName: g.scanResults.isEmpty ? "checkmark.seal.fill" : "exclamationmark.triangle.fill")
                                .foregroundStyle(g.scanResults.isEmpty ? .green : .red)
                        }
                        VStack(alignment: .leading, spacing: 2) {
                            Text(g.scanMessage).font(.headline)
                            if let f = g.scanFolder { Text(f).font(.caption).foregroundStyle(.secondary).truncationMode(.middle).lineLimit(1) }
                        }
                        Spacer()
                        if !g.scanResults.isEmpty, let folder = g.scanFolder {
                            Button("Move All to Quarantine") { g.scan(folder, quarantine: true) }
                                .buttonStyle(.borderedProminent).tint(.red)
                        }
                    }
                    if !g.scanResults.isEmpty {
                        Divider()
                        List(g.scanResults) { f in
                            FindingRow(name: (f.path as NSString).lastPathComponent, detail: "\(f.reason) · \(f.path)", date: nil) { g.reveal(f.path) }
                        }
                        .listStyle(.plain)
                        .frame(minHeight: 160, maxHeight: 300)
                    }
                }
            }
            Spacer()
        }
        .padding(24)
        .navigationTitle("Scan")
    }
}

// MARK: - Quarantine

struct QuarantineView: View {
    @EnvironmentObject var g: Guard
    @State private var selection = Set<String>()
    @State private var confirmDelete = false
    @State private var message: String?

    var selected: [Incident] { g.incidents.filter { selection.contains($0.id) } }

    var body: some View {
        VStack(spacing: 0) {
            if g.incidents.isEmpty {
                ContentUnavailableView("Quarantine is empty", systemImage: "archivebox",
                                       description: Text("Files Fontguard moves out of harm's way are kept here, never deleted automatically."))
            } else {
                List(g.incidents, selection: $selection) { i in
                    HStack(spacing: 12) {
                        Image(systemName: i.source == "watch" ? "bolt.shield.fill" : i.source == "scan" ? "magnifyingglass.circle.fill" : "arrow.triangle.branch")
                            .font(.title3).foregroundStyle(.secondary).frame(width: 26)
                        VStack(alignment: .leading, spacing: 3) {
                            Text(title(i)).fontWeight(.medium).lineLimit(1)
                            Text(i.files.prefix(3).map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
                                 + (i.files.count > 3 ? " and \(i.files.count - 3) more" : ""))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        VStack(alignment: .trailing, spacing: 3) {
                            if let d = i.date { Text(d, format: .dateTime.day().month().hour().minute()).font(.caption) }
                            Text("\(i.files.count) file(s) · \(ByteCountFormatter.string(fromByteCount: i.size, countStyle: .file))")
                                .font(.caption2).foregroundStyle(.secondary)
                        }
                    }
                    .padding(.vertical, 4)
                    .contextMenu {
                        Button("Show in Finder") { g.reveal(quarantineDir + "/" + i.folder) }
                    }
                }
            }
            Divider()
            HStack {
                Text("\(g.incidents.count) incident(s), \(g.quarantinedFiles) file(s)").font(.caption).foregroundStyle(.secondary)
                if let message { Text(message).font(.caption).foregroundStyle(.orange).lineLimit(1) }
                Spacer()
                Button("Show in Finder") {
                    if let i = selected.first { g.reveal(quarantineDir + "/" + i.folder) } else { g.openQuarantineFolder() }
                }
                Button("Restore") {
                    message = selected.compactMap { g.restore($0) }.first
                    selection.removeAll()
                }
                .disabled(selected.isEmpty || selected.contains { !$0.restorable })
                .help("Puts the files back. Pause protection first, or Fontguard will catch them again if they still look infected.")
                Button("Delete…", role: .destructive) { confirmDelete = true }
                    .disabled(selected.isEmpty)
            }
            .padding(12)
        }
        .navigationTitle("Quarantine")
        .toolbar { Button { g.reload() } label: { Label("Refresh", systemImage: "arrow.clockwise") } }
        .confirmationDialog("Permanently delete \(selected.reduce(0) { $0 + $1.files.count }) file(s)?", isPresented: $confirmDelete) {
            Button("Delete Permanently", role: .destructive) { g.delete(selected); selection.removeAll() }
        } message: {
            Text("This can't be undone. Keep files you might need as evidence.")
        }
    }

    func title(_ i: Incident) -> String {
        switch i.source {
        case "watch": return "Caught in real time"
        case "scan": return "Moved by a scan"
        case "manual": return i.folder.dropFirst(16).replacingOccurrences(of: "-", with: " ").capitalized
        default: return "Caught on clone or pull: \(i.source)"
        }
    }
}

// MARK: - Activity

struct ActivityView: View {
    @EnvironmentObject var g: Guard
    @State private var query = ""

    var rows: [LogEntry] { query.isEmpty ? g.activity : g.activity.filter { $0.text.localizedCaseInsensitiveContains(query) } }

    var body: some View {
        Group {
            if g.activity.isEmpty {
                ContentUnavailableView("No activity yet", systemImage: "list.bullet.rectangle")
            } else {
                List(rows) { e in
                    HStack(alignment: .top, spacing: 10) {
                        Image(systemName: e.kind == .caught ? "ladybug.fill" : e.kind == .blocked ? "lock.fill" : "info.circle")
                            .foregroundStyle(e.kind == .caught ? .red : e.kind == .blocked ? .orange : .secondary)
                            .frame(width: 18)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(summary(e)).font(.callout)
                            Text(e.text).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(2).truncationMode(.middle)
                        }
                        Spacer()
                        if let d = e.date { Text(d, format: .dateTime.day().month().hour().minute()).font(.caption).foregroundStyle(.tertiary) }
                    }
                    .padding(.vertical, 3)
                }
            }
        }
        .searchable(text: $query, prompt: "Search activity")
        .navigationTitle("Activity")
        .toolbar { Button { g.reload() } label: { Label("Refresh", systemImage: "arrow.clockwise") } }
    }

    func summary(_ e: LogEntry) -> String {
        switch e.kind {
        case .caught:
            let f = parse(e.text, date: e.date)
            let name = ((f?.path ?? "") as NSString).lastPathComponent
            let reason = (f?.reason.isEmpty ?? true) ? "" : ": \(f!.reason)"
            return (e.text.contains("-> stopped") ? "Stopped \(name)" : "Quarantined \(name)") + reason
        case .blocked: return "Couldn't check a file (needs Full Disk Access)"
        case .info: return e.text.hasPrefix("fontguard: watching") ? "Real-time protection started" : "Fontguard"
        }
    }
}

// MARK: - Window and menu bar

struct RootView: View {
    @EnvironmentObject var g: Guard

    var body: some View {
        NavigationSplitView {
            List(selection: $g.pane) {
                Label("Overview", systemImage: "shield.lefthalf.filled").tag(Pane.overview)
                Label("Scan", systemImage: "magnifyingglass").tag(Pane.scan)
                Label { Text("Quarantine") } icon: { Image(systemName: "archivebox") }
                    .badge(g.incidents.count)
                    .tag(Pane.quarantine)
                Label("Activity", systemImage: "list.bullet.rectangle").tag(Pane.activity)
            }
            .navigationSplitViewColumnWidth(min: 180, ideal: 200)
        } detail: {
            switch g.pane {
            case .overview: OverviewView()
            case .scan: ScanView()
            case .quarantine: QuarantineView()
            case .activity: ActivityView()
            }
        }
        .frame(minWidth: 880, minHeight: 580)
    }
}

struct MenuContent: View {
    @ObservedObject var g: Guard
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Text(g.title)
        Divider()
        Button("Open Fontguard") { show(.overview) }
        Button("Scan a Folder…") { show(.scan); g.pickAndScan() }
        Button(g.paused ? "Resume Protection" : "Pause Protection") { g.paused ? g.start() : g.pause() }
        Divider()
        Button("Quit Fontguard") { NSApp.terminate(nil) }
    }

    func show(_ pane: Pane) {
        g.pane = pane
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

struct MenuLabel: View {
    @ObservedObject var g: Guard
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Image(systemName: g.icon)
            .onAppear {
                // Lets a second launch from Finder bring the window back.
                g.openMain = { openWindow(id: "main"); NSApp.activate(ignoringOtherApps: true) }
            }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        MainActor.assumeIsolated {
            if let open = Guard.shared.openMain {
                open()
            } else {
                NSApp.windows.first { $0.identifier?.rawValue == "main" }?.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            }
        }
        return true
    }

    func applicationWillTerminate(_ notification: Notification) {
        MainActor.assumeIsolated { Guard.shared.shutdown() }
    }
}

@main
struct FontguardApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    @StateObject private var g = Guard.shared
    // The login agent sets FONTGUARD_BACKGROUND (see the plist in build.sh); opening from Finder shows the window.
    private let background = CommandLine.arguments.contains("--background")
        || ProcessInfo.processInfo.environment["FONTGUARD_BACKGROUND"] != nil

    var body: some Scene {
        Window("Fontguard", id: "main") {
            RootView().environmentObject(g)
        }
        .defaultSize(width: 960, height: 640)
        .defaultPosition(.center)
        .defaultLaunchBehavior(background ? .suppressed : .presented)

        MenuBarExtra {
            MenuContent(g: g)
        } label: {
            MenuLabel(g: g)
        }
    }
}
