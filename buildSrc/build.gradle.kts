plugins {
    `kotlin-dsl`
}

repositories {
    gradlePluginPortal()
    mavenCentral()
}

dependencies {
    implementation(libs.spring.boot.gradlePlugin)
    implementation(libs.spring.dependencyManagement.gradlePlugin)
}
