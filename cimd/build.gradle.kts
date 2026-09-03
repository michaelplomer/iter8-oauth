plugins {
    id("mcpoauth.java-library-conventions")
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

// Client ID Metadata Documents: fetching + validating a client's self-description, and verifying
// private_key_jwt assertions. Provider-neutral — consumed by the AS engine.
dependencies {
    implementation(libs.spring.boot.starter.webflux) // WebClient, Reactor, Jackson 3
    implementation(libs.nimbus.jose.jwt)             // JWS/JWK for client assertions
}
