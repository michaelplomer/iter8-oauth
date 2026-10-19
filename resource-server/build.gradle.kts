plugins {
    id("buildlogic.java-library-conventions")
    `maven-publish`
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
}

// The consumer-side validation library the MCP servers depend on: protected-resource metadata, the bearer
// challenge, and a security chain that validates AS-issued tokens (JWS via JWKS, or JWE via the
// self-issued introspector).
dependencies {
    api(project(":token"))                                       // JweTokenCodec, TokenKeys, IssuedToken
    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.oauth2.resource.server)
}
