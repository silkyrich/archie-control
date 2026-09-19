import SwiftUI

@MainActor
final class Model: ObservableObject {
    @Published var status: Status?
    @Published var usage: Usage?
    @Published var busy = false
    @Published var error: String?
    @Published var signedOut = false

    func refresh() async {
        do {
            async let s = API.shared.status()
            async let u = API.shared.usage()
            status = try await s
            usage = try await u
            error = nil
        } catch APIError.signedOut {
            signedOut = true
        } catch {
            self.error = error.localizedDescription
        }
    }

    func run(_ op: @escaping () async throws -> Status) async {
        busy = true
        defer { busy = false }
        do {
            status = try await op()
            error = nil
            usage = try? await API.shared.usage()
        } catch APIError.signedOut {
            signedOut = true
        } catch {
            self.error = error.localizedDescription
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var auth: Auth
    @StateObject private var model = Model()
    @State private var tick = Date()
    private let timer = Timer.publish(every: 30, on: .main, in: .common).autoconnect()

    var body: some View {
        NavigationStack {
            Group {
                if !auth.signedIn || model.signedOut {
                    signIn
                } else {
                    main
                }
            }
            .navigationTitle("Archie")
            .toolbar {
                if auth.signedIn && !model.signedOut {
                    ToolbarItem(placement: .topBarTrailing) {
                        Menu(auth.email ?? "") {
                            Button("Sign out", role: .destructive) { auth.signOut(); model.signedOut = true }
                        }
                    }
                }
            }
        }
        .task { await model.refresh() }
        .onReceive(timer) { now in
            tick = now
            Task { await model.refresh() }
        }
    }

    // MARK: sign in

    private var signIn: some View {
        VStack(spacing: 20) {
            Image(systemName: "gamecontroller").font(.system(size: 56)).foregroundStyle(.tint)
            Text("Sign in with the family Google account to see and change Archie's rules.")
                .multilineTextAlignment(.center).foregroundStyle(.secondary)
            Button {
                model.signedOut = false
                auth.signIn()
            } label: {
                Text("Sign in with Google").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent).controlSize(.large)
            if let e = auth.error { Text(e).font(.footnote).foregroundStyle(.red) }
        }
        .padding(32)
        .onChange(of: auth.email) { _, new in
            if new != nil { Task { await model.refresh() } }
        }
    }

    // MARK: main

    private var main: some View {
        List {
            if let e = model.error {
                Section { Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.red) }
            }
            if let s = model.status {
                Section("Right now") { summary(s) }
                Section("Rules") { ForEach(s.rules) { ruleRow($0) } }
                Section("Let him on") { allowButtons(s) }
            } else {
                Section { ProgressView("Loading…") }
            }
            if let u = model.usage {
                Section("Today on his devices") {
                    ForEach(u.devices) { deviceRow($0) }
                }
            }
        }
        .refreshable { await model.refresh() }
        .disabled(model.busy)
        .overlay { if model.busy { ProgressView().controlSize(.large) } }
    }

    private func summary(_ s: Status) -> some View {
        let blocking = s.rules.filter(\.blocking)
        let overridden = s.rules.compactMap(\.override).map(\.until).max()
        return VStack(alignment: .leading, spacing: 6) {
            if let until = overridden, until > tick {
                Label("Allowed until \(until.formatted(date: .omitted, time: .shortened))", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green).font(.headline)
                Text(countdown(to: until)).foregroundStyle(.secondary)
            } else if blocking.isEmpty {
                Label("Nothing blocked right now", systemImage: "moon.zzz").font(.headline)
            } else {
                Label("\(blocking.count) of \(s.rules.count) rules blocking (school hours)", systemImage: "hand.raised.fill")
                    .foregroundStyle(.orange).font(.headline)
            }
            if !s.engine.ok {
                Label("Home controller hasn't checked in for a while", systemImage: "wifi.exclamationmark")
                    .font(.footnote).foregroundStyle(.red)
            }
        }
    }

    private func ruleRow(_ r: Rule) -> some View {
        HStack {
            Circle().fill(r.blocking ? .orange : (r.enabled ? .gray.opacity(0.4) : .green)).frame(width: 10, height: 10)
            VStack(alignment: .leading) {
                Text(r.name)
                Text(r.override.map { "paused until \($0.until.formatted(date: .omitted, time: .shortened))" } ?? r.schedule.label)
                    .font(.footnote).foregroundStyle(.secondary)
            }
            Spacer()
            Text(r.blocking ? "blocking" : (r.enabled ? "idle" : "paused")).font(.footnote).foregroundStyle(.secondary)
        }
    }

    private func allowButtons(_ s: Status) -> some View {
        let paused = s.rules.contains { $0.override != nil }
        return VStack(spacing: 10) {
            HStack {
                allow("30 min", minutes: 30)
                allow("1 hour", minutes: 60)
                allow("2 hours", minutes: 120)
            }
            HStack {
                allow("Until 5pm", until: "17:00")
                allow("Until 9pm", until: "21:00")
            }
            HStack {
                Button(role: .destructive) {
                    Task { await model.run { try await API.shared.revoke() } }
                } label: { Label("Back to rules", systemImage: "arrow.uturn.backward").frame(maxWidth: .infinity) }
                .buttonStyle(.bordered).disabled(!paused)
                Button {
                    Task { await model.run { try await API.shared.flush() } }
                } label: { Label("Kick him off", systemImage: "bolt.slash").frame(maxWidth: .infinity) }
                .buttonStyle(.bordered).tint(.orange)
            }
            Text("Allowing pauses every rule. Rules come back on their own when the time is up. Kick off cuts whatever he has open right now.")
                .font(.caption2).foregroundStyle(.secondary)
        }
        .buttonStyle(.borderedProminent)
        .padding(.vertical, 4)
    }

    private func allow(_ title: String, minutes: Int? = nil, until: String? = nil) -> some View {
        Button(title) {
            Task { await model.run { try await API.shared.allow(target: "all", minutes: minutes, until: until, reason: "app") } }
        }
        .frame(maxWidth: .infinity)
    }

    private func deviceRow(_ d: DeviceUsage) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(d.device).font(.headline)
                Spacer()
                if let f = d.first_seen {
                    Text("from \(f.formatted(date: .omitted, time: .shortened))").foregroundStyle(.secondary)
                } else {
                    Text("not seen today").foregroundStyle(.secondary)
                }
            }
            if d.online_minutes > 0 || d.down_mb > 0 {
                Text("\(d.online_minutes / 60)h \(d.online_minutes % 60)m online · \(Int(d.down_mb)) MB down")
                    .font(.footnote).foregroundStyle(.secondary)
            }
            if !d.categories.isEmpty {
                Text(d.categories.prefix(3).map { "\($0.name) \(Int($0.mb)) MB" }.joined(separator: " · "))
                    .font(.footnote)
            }
            if !d.timeline.isEmpty { sparkline(d.timeline) }
        }
        .padding(.vertical, 2)
    }

    private func sparkline(_ pts: [TimelinePoint]) -> some View {
        let maxMB = max(pts.map(\.mb).max() ?? 1, 1)
        return HStack(alignment: .bottom, spacing: 2) {
            ForEach(pts) { p in
                RoundedRectangle(cornerRadius: 1)
                    .fill(.tint.opacity(0.7))
                    .frame(width: 6, height: max(2, 28 * p.mb / maxMB))
                    .help(p.at.formatted(date: .omitted, time: .shortened))
            }
        }
        .frame(height: 28)
    }

    private func countdown(to until: Date) -> String {
        let s = Int(until.timeIntervalSince(tick))
        return s <= 0 ? "ending now" : "\(s / 3600 > 0 ? "\(s / 3600)h " : "")\(s % 3600 / 60)m left"
    }
}
