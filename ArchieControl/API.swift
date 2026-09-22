import Foundation
import Security

enum APIError: LocalizedError {
    case signedOut
    case server(String)

    var errorDescription: String? {
        switch self {
        case .signedOut: return "Signed out. Sign in again."
        case .server(let m): return m
        }
    }
}

/// Talks to rules.richmorgan.co.uk. Cloudflare Access sits in front and
/// accepts the sign-in JWT in the `cf-access-token` header; the green PC
/// behind it only sees requests Access has already authenticated.
final class API {
    static let base = URL(string: "https://rules.richmorgan.co.uk")!
    /// The engine manages people as groups; this app is for one of them.
    static let group = "archie"
    static let shared = API()

    func status() async throws -> Status { try await get("/api/\(Self.group)/status") }
    func usage() async throws -> Usage { try await get("/api/\(Self.group)/usage") }

    func allow(target: String, minutes: Int? = nil, until: String? = nil, reason: String) async throws -> Status {
        var body: [String: Any] = ["target": target, "reason": reason]
        if let m = minutes { body["minutes"] = m }
        if let u = until { body["until"] = u }
        return try await post("/api/\(Self.group)/allow", body)
    }
    func revoke(target: String = "all") async throws -> Status { try await post("/api/\(Self.group)/revoke", ["target": target]) }
    func flush(target: String = "all") async throws -> Status { try await post("/api/\(Self.group)/flush", ["target": target]) }

    private func get<T: Decodable>(_ path: String) async throws -> T {
        try await send(request(path, method: "GET", body: nil))
    }
    private func post<T: Decodable>(_ path: String, _ body: [String: Any]) async throws -> T {
        try await send(request(path, method: "POST", body: try JSONSerialization.data(withJSONObject: body)))
    }

    private func request(_ path: String, method: String, body: Data?) -> URLRequest {
        var r = URLRequest(url: Self.base.appendingPathComponent(path))
        r.httpMethod = method
        r.httpBody = body
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        if let t = Keychain.token { r.setValue(t, forHTTPHeaderField: "cf-access-token") }
        return r
    }

    private func send<T: Decodable>(_ req: URLRequest) async throws -> T {
        let (data, resp) = try await URLSession.shared.data(for: req)
        let http = resp as? HTTPURLResponse
        // With no valid token Access answers the login page (HTML), not JSON.
        let isJSON = (http?.value(forHTTPHeaderField: "Content-Type") ?? "").contains("json")
        if http?.statusCode == 401 || http?.statusCode == 403 || !isJSON { throw APIError.signedOut }
        if http?.statusCode != 200 {
            let msg = (try? JSONDecoder().decode([String: String].self, from: data))?["error"] ?? "HTTP \(http?.statusCode ?? 0)"
            throw APIError.server(msg)
        }
        return try JSONDecoder.api.decode(T.self, from: data)
    }
}

/// The Access JWT and the signed-in email, in the keychain.
enum Keychain {
    static var token: String? {
        get { read("token") }
        set { write("token", newValue) }
    }
    static var email: String? {
        get { read("email") }
        set { write("email", newValue) }
    }

    private static func query(_ key: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.silkyrich.archiecontrol",
         kSecAttrAccount as String: key]
    }
    private static func read(_ key: String) -> String? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: AnyObject?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return String(data: d, encoding: .utf8)
    }
    private static func write(_ key: String, _ value: String?) {
        SecItemDelete(query(key) as CFDictionary)
        guard let v = value?.data(using: .utf8) else { return }
        var q = query(key)
        q[kSecValueData as String] = v
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        SecItemAdd(q as CFDictionary, nil)
    }
}
