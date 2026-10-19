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

// The token formats the authorization server issues and resource servers validate: the JWS and JWE codecs,
// the token model and claims, and the keys that sign and seal tokens. It has no Spring dependency, so
// validating a token does not bring in the authorization server.
dependencies {
    api(libs.nimbus.jose.jwt)                 // JWK types appear in the public API
    implementation("org.slf4j:slf4j-api")
}
