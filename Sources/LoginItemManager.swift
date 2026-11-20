import Foundation
import ServiceManagement

enum LoginItemState: Equatable, Sendable {
    case enabled
    case requiresApproval
    case disabled
    case unavailable(String)

    var isEnabled: Bool {
        self == .enabled
    }

    var label: String {
        switch self {
        case .enabled: "已开启开机自启"
        case .requiresApproval: "需在系统设置→登录项中允许"
        case .disabled: "未开启"
        case .unavailable(let reason): reason
        }
    }
}

enum LoginItemManager {
    private static var isBundledApp: Bool {
        Bundle.main.bundleURL.pathExtension == "app" && Bundle.main.bundleIdentifier != nil
    }

    static func currentState() -> LoginItemState {
        guard isBundledApp else {
            return .unavailable("仅支持从 .app 应用包启用")
        }
        switch SMAppService.mainApp.status {
        case .enabled:
            return .enabled
        case .requiresApproval:
            return .requiresApproval
        case .notRegistered, .notFound:
            return .disabled
        @unknown default:
            return .disabled
        }
    }

    static func setEnabled(_ enabled: Bool) throws -> LoginItemState {
        guard isBundledApp else {
            throw NSError(
                domain: "local.claude-environment-check.loginitem",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "请从 /Applications/Claude 环境体检.app 运行后再开启登录自启。"]
            )
        }
        if enabled {
            try SMAppService.mainApp.register()
        } else {
            try SMAppService.mainApp.unregister()
        }
        return currentState()
    }
}
