import SwiftUI

@main
struct ArchieControlApp: App {
    @StateObject private var auth = Auth()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .onOpenURL { url in
                    // Fallback for the sign-in bounce if the web session hands it
                    // to the app via the URL scheme instead of its completion.
                    if url.host == "auth" { auth.handle(url) }
                }
        }
    }
}
