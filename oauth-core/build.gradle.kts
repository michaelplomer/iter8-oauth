plugins {
    id("buildlogic.published-library-conventions")
}

description = "The iter8-oauth authorization server engine, with pluggable upstream providers."

// The authorization server engine: PKCE, the code and pending-authorization stores, the endpoints, and the
// UpstreamProvider SPI with its brokered and OIDC providers. Token formats and codecs live in the token
// module, and the deployable app in as-app.
dependencies {
    api(project(":cimd"))                            // client onboarding types leak into the SPI/endpoints
    api(project(":token"))                           // token model and codecs appear in the SPI
    implementation(libs.spring.boot.starter.webflux) // ServerWebExchange, WebClient, Reactor
    implementation(libs.nimbus.jose.jwt)             // JWE/JWS/JWK
}
