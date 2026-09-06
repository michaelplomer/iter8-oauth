plugins {
    id("mcpoauth.java-library-conventions")
    `maven-publish`
    id("com.google.cloud.artifactregistry.gradle-plugin")
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            versionMapping {
                usage("java-api") { fromResolutionResult() }
                usage("java-runtime") { fromResolutionResult() }
            }
        }
    }
    repositories {
        maven {
            name = "artifactRegistry"
            url = uri("artifactregistry://us-west1-maven.pkg.dev/plomer-platform/maven")
        }
    }
}

// The consumer-side validation library the MCP servers depend on: protected-resource metadata, the bearer
// challenge, and a security chain that validates AS-issued tokens (JWS via JWKS, or JWE via the
// self-issued introspector).
dependencies {
    api(project(":oauth-core"))                                  // JweTokenCodec, TokenKeys, IssuedToken
    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.oauth2.resource.server)
}
