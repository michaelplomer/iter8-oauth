import org.springframework.boot.gradle.tasks.bundling.BootJar

/**
 * For runnable Spring Boot applications: everything from the library conventions, but with the executable
 * bootJar enabled and the plain jar disabled.
 */
plugins {
    id("mcpoauth.java-library-conventions")
}

tasks.named<BootJar>("bootJar") { enabled = true }
tasks.named<Jar>("jar") { enabled = false }
