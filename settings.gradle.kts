rootProject.name = "mcp-oauth"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositories {
        mavenCentral()
    }
}

// Modules land here as each is implemented:
//   :cimd            client-id metadata documents (provider-neutral) — published
//   :oauth-core      AS engine + UpstreamProvider/IssuedTokenCodec SPIs
//   :resource-server validation library consumed by the MCP servers — published
//   :as-app          the deployable authorization server (not published)
include(":cimd")
include(":oauth-core")
include(":resource-server")
include(":as-app")
