plugins {
    id("buildlogic.published-library-conventions")
}

description = "Validates iter8-oauth access tokens for MCP servers built with Spring WebFlux."

// The consumer-side validation library the MCP servers depend on: protected-resource metadata, the bearer
// challenge, and a security chain that validates AS-issued tokens (JWS via JWKS, or JWE via the
// self-issued introspector).
dependencies {
    api(project(":token"))                                       // JweTokenCodec, TokenKeys, IssuedToken
    implementation(libs.spring.boot.starter.webflux)
    implementation(libs.spring.boot.starter.oauth2.resource.server)
}
