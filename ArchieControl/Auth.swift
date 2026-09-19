import AuthenticationServices
import SwiftUI

/// Sign-in is Cloudflare Access with Google. We open /auth/start in a system
/// web session; Access does the Google login, then the green PC bounces the
/// browser to archiecontrol://auth?token=…&email=… and we keep the token.
@MainActor
final class Auth: NSObject, ObservableObject, ASWebAuthenticationPresentationContextProviding {
    @Published var email: String? = Keychain.email
    @Published var error: String?

    var signedIn: Bool { Keychain.token != nil }

    func signIn() {
        let url = API.base.appendingPathComponent("/auth/start")
        let session = ASWebAuthenticationSession(url: url, callbackURLScheme: "archiecontrol") { [weak self] cb, err in
            Task { @MainActor in
                guard let self else { return }
                if let err { self.error = err.localizedDescription; return }
                self.handle(cb)
            }
        }
        session.presentationContextProvider = self
        session.prefersEphemeralWebBrowserSession = false  // reuse the Google login already in Safari
        session.start()
    }

    func handle(_ url: URL?) {
        guard let url, let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
              let token = items.first(where: { $0.name == "token" })?.value else {
            error = "Sign-in did not return a token."
            return
        }
        Keychain.token = token
        Keychain.email = items.first(where: { $0.name == "email" })?.value
        email = Keychain.email
        error = nil
    }

    func signOut() {
        Keychain.token = nil
        Keychain.email = nil
        email = nil
    }

    nonisolated func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        MainActor.assumeIsolated {
            UIApplication.shared.connectedScenes
                .compactMap { $0 as? UIWindowScene }
                .flatMap(\.windows)
                .first { $0.isKeyWindow } ?? ASPresentationAnchor()
        }
    }
}
