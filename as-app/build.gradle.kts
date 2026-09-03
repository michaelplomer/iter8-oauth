plugins {
    id("mcpoauth.spring-boot-app-conventions")
}

// The deployable authorization server: wires the oauth-core engine and both providers from declarative
// configuration, and serves the /oauth2/* and /.well-known/* endpoints. Not published.
dependencies {
    implementation(project(":oauth-core"))
    implementation(libs.spring.boot.starter.webflux)
}
