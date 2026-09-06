rootProject.name = "mcp-oauth"

pluginManagement {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
    // The Artifact Registry transport for `artifactregistry://` publish URLs. Version pinned here so the
    // library modules can apply it without repeating the version. Resolved from the Gradle Plugin Portal.
    plugins {
        id("com.google.cloud.artifactregistry.gradle-plugin") version "2.2.5"
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
