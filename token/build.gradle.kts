plugins {
    id("buildlogic.published-library-conventions")
}

description = "Token formats, codecs and keys shared by the iter8-oauth authorization and resource servers."

// The token formats the authorization server issues and resource servers validate: the JWS and JWE codecs,
// the token model and claims, and the keys that sign and seal tokens. It has no Spring dependency, so
// validating a token does not bring in the authorization server.
dependencies {
    api(libs.nimbus.jose.jwt)                 // JWK types appear in the public API
    implementation("org.slf4j:slf4j-api")
}
