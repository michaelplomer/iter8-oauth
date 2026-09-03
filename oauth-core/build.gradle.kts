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

// The authorization-server engine: PKCE, code/pending stores, the token layer (JWE-carry-secret and
// JWS-identity codecs), and the UpstreamProvider / IssuedTokenCodec SPIs. Provider-neutral; concrete
// providers and the deployable app live elsewhere.
dependencies {
    api(project(":cimd"))                            // client onboarding types leak into the SPI/endpoints
    implementation(libs.spring.boot.starter.webflux) // ServerWebExchange, WebClient, Reactor
    implementation(libs.nimbus.jose.jwt)             // JWE/JWS/JWK
}
