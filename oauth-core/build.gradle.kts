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
        // The central shared Maven repo in the platform project (created by plomer.info-gcp-org). Publishing
        // needs a writer on it (the CI build SA / a developer's ADC); `publishToMavenLocal` still works for
        // local dev. See gradle/README or the org repo for the reader/writer wiring.
        maven {
            name = "artifactRegistry"
            url = uri("artifactregistry://us-west1-maven.pkg.dev/plomer-platform/maven")
        }
    }
}

// The authorization-server engine: PKCE, code/pending stores, the token layer (JWE-carry-secret and
// JWS-identity codecs), and the UpstreamProvider / IssuedTokenCodec SPIs. Provider-neutral; concrete
// providers and the deployable app live elsewhere.
dependencies {
    api(project(":cimd"))                            // client onboarding types leak into the SPI/endpoints
    api(project(":token"))                           // token model and codecs appear in the SPI
    implementation(libs.spring.boot.starter.webflux) // ServerWebExchange, WebClient, Reactor
    implementation(libs.nimbus.jose.jwt)             // JWE/JWS/JWK
}
