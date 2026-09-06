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

// Client ID Metadata Documents: fetching + validating a client's self-description, and verifying
// private_key_jwt assertions. Provider-neutral — consumed by the AS engine.
dependencies {
    implementation(libs.spring.boot.starter.webflux) // WebClient, Reactor, Jackson 3
    implementation(libs.nimbus.jose.jwt)             // JWS/JWK for client assertions
}
