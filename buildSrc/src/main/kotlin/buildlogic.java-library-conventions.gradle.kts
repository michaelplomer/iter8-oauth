import org.springframework.boot.gradle.tasks.bundling.BootJar

/**
 * Shared build logic for the JVM library modules: Java 25 toolchain, Spring Boot BOM (for managed
 * dependency versions), Lombok, and JUnit. The Spring Boot plugin is applied only for its
 * dependency management; the executable bootJar is disabled here and re-enabled by the app convention.
 */
plugins {
    `java-library`
    id("org.springframework.boot")
    id("io.spring.dependency-management")
}

// The version lives in gradle.properties, so a release build can override it with -Pversion.
group = "de.iter8"

// Library default: a plain jar, not a runnable bootJar. Clear the "plain" classifier the Spring Boot
// plugin adds, so the library publishes as the main artifact (no classifier) that consumers resolve.
tasks.named<BootJar>("bootJar") { enabled = false }
tasks.named<Jar>("jar") {
    enabled = true
    archiveClassifier.set("")
}

java {
    toolchain { languageVersion = JavaLanguageVersion.of(25) }
}

// Compile with JDK 25 but emit Java 17 bytecode, so these libraries are consumable by any JVM >= 17.
// Spring Boot 4.1's own baseline is 17, so this fits.
tasks.withType<JavaCompile>().configureEach {
    options.release.set(17)
}

repositories {
    mavenCentral()
}

dependencies {
    "compileOnly"("org.projectlombok:lombok")
    "annotationProcessor"("org.projectlombok:lombok")
    "testCompileOnly"("org.projectlombok:lombok")
    "testAnnotationProcessor"("org.projectlombok:lombok")

    "testImplementation"("org.springframework.boot:spring-boot-starter-test")
    "testImplementation"("io.projectreactor:reactor-test")
}

tasks.withType<Test> { useJUnitPlatform() }
