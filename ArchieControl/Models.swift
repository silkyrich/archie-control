import Foundation

/// Mirrors the JSON from api.py on the green PC.
struct Status: Codable {
    var now: Date
    var rules: [Rule]
    var engine: Engine
}

struct Engine: Codable {
    var last_tick_s_ago: Int?
    var ok: Bool
}

struct Rule: Codable, Identifiable {
    var id: String
    var name: String
    var enabled: Bool
    var blocking: Bool
    var schedule: Schedule
    var override: Override?

    enum Schedule: Codable {
        case always
        case weekly(days: [String], start: String, end: String)

        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let s = try? c.decode(String.self), s == "always" { self = .always; return }
            struct W: Codable { var days: [String]?; var start: String?; var end: String? }
            let w = try c.decode(W.self)
            self = .weekly(days: w.days ?? [], start: w.start ?? "", end: w.end ?? "")
        }
        func encode(to encoder: Encoder) throws {}

        var label: String {
            switch self {
            case .always: return "always"
            case let .weekly(days, start, end):
                let d = days.count == 5 && !days.contains("sat") ? "Mon–Fri" : days.map { $0.capitalized }.joined(separator: " ")
                return "\(d) \(start)–\(end)"
            }
        }
    }
}

struct Override: Codable {
    var until: Date
    var reason: String?
    var set_at: Date?
}

struct Usage: Codable {
    var day: String
    var now: Date
    var devices: [DeviceUsage]
}

struct DeviceUsage: Codable, Identifiable {
    var id: String { device }
    var device: String
    var first_seen: Date?
    var last_seen: Date?
    var online_minutes: Int
    var down_mb: Double
    var up_mb: Double
    var categories: [Category]
    var timeline: [TimelinePoint]
}

struct Category: Codable, Identifiable {
    var id: String { name }
    var name: String
    var mb: Double
}

struct TimelinePoint: Codable, Identifiable {
    var id: Date { at }
    var at: Date
    var mb: Double
}

/// The API emits ISO-8601 with offsets and, for the usage timestamps, without
/// seconds. One decoder handles both.
extension JSONDecoder {
    static let api: JSONDecoder = {
        let d = JSONDecoder()
        let full = ISO8601DateFormatter()
        full.formatOptions = [.withInternetDateTime]
        let short = ISO8601DateFormatter()
        short.formatOptions = [.withFullDate, .withTime, .withColonSeparatorInTime, .withTimeZone]
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            if let v = full.date(from: s) ?? short.date(from: s) { return v }
            throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad date \(s)"))
        }
        return d
    }()
}
