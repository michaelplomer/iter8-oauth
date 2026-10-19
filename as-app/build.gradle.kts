plugins {
    id("buildlogic.spring-boot-app-conventions")
    alias(libs.plugins.jib)
}

// The deployable authorization server: wires the oauth-core engine and both providers from declarative
// configuration, and serves the /oauth2/* and /.well-known/* endpoints. Not published.
dependencies {
    implementation(project(":oauth-core"))
    implementation(libs.spring.boot.starter.webflux)
}

// The container image, published to GitHub's container registry by CI. The workflow that pushes it names the
// image with its primary tag, since an image name without one means latest, which only releases may move.
// The registry credentials come from the environment rather than the command line.
jib {
    from {
        image = "eclipse-temurin:25-jre"
        platforms {
            platform {
                architecture = "amd64"
                os = "linux"
            }
            platform {
                architecture = "arm64"
                os = "linux"
            }
        }
    }
    to {
        image = "ghcr.io/michaelplomer/iter8-oauth"
        auth {
            username = providers.environmentVariable("REGISTRY_USERNAME").orNull
            password = providers.environmentVariable("REGISTRY_PASSWORD").orNull
        }
    }
    container {
        mainClass = "de.iter8.oauth.AuthorizationServerApplication"
        ports = listOf("8080")
        // Any non-root user; the server writes nothing to disk.
        user = "1000:1000"
        jvmFlags = listOf("-XX:MaxRAMPercentage=75", "-XX:+UseSerialGC")
        // The commit and build time are only known in CI. Without them the base image's own creation time
        // would show through, so CI always sets IMAGE_CREATED.
        labels.set(
            mapOf(
                "org.opencontainers.image.title" to "iter8-oauth",
                "org.opencontainers.image.description" to "An OAuth 2.1 authorization server for MCP servers.",
                "org.opencontainers.image.source" to "https://github.com/michaelplomer/iter8-oauth",
                "org.opencontainers.image.licenses" to "Apache-2.0",
                "org.opencontainers.image.version" to project.version.toString(),
                "org.opencontainers.image.revision" to providers.environmentVariable("GITHUB_SHA").orNull,
                "org.opencontainers.image.created" to providers.environmentVariable("IMAGE_CREATED").orNull,
            ).filterValues { it != null }.mapValues { it.value!! }
        )
    }
}
