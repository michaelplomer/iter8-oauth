/**
 * For the library modules that are published to Maven Central: everything from the library conventions,
 * plus signed publishing with the POM metadata Central requires. Each module sets only its own description.
 *
 * Credentials and the signing key come from Gradle properties, which CI sets from secrets:
 * mavenCentralUsername, mavenCentralPassword, signingInMemoryKey and signingInMemoryKeyPassword.
 */
plugins {
    id("buildlogic.java-library-conventions")
    id("com.vanniktech.maven.publish")
}

mavenPublishing {
    publishToMavenCentral()
    signAllPublications()

    pom {
        name.set("iter8-oauth ${project.name}")
        description.set(project.provider { project.description })
        url.set("https://github.com/michaelplomer/iter8-oauth")
        inceptionYear.set("2026")
        licenses {
            license {
                name.set("Apache License, Version 2.0")
                url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                distribution.set("repo")
            }
        }
        developers {
            developer {
                id.set("michaelplomer")
                name.set("Michael Plomer")
                url.set("https://github.com/michaelplomer")
            }
        }
        scm {
            url.set("https://github.com/michaelplomer/iter8-oauth")
            connection.set("scm:git:https://github.com/michaelplomer/iter8-oauth.git")
            developerConnection.set("scm:git:ssh://git@github.com/michaelplomer/iter8-oauth.git")
        }
    }
}

// Publish the versions that were actually resolved, so the POM is complete without Spring Boot's BOM, and leave
// the BOM import out of it: imported into a consumer's build, it could override the consumer's own versions.
dependencyManagement {
    generatedPomCustomization { enabled(false) }
}

publishing {
    publications.withType<MavenPublication>().configureEach {
        versionMapping {
            usage("java-api") { fromResolutionResult() }
            usage("java-runtime") { fromResolutionResult() }
        }
    }
}

// Javadoc's checks stay on, except the one that flags members without a description of their own: many are
// documented through their @param and @return tags alone.
tasks.withType<Javadoc>().configureEach {
    (options as StandardJavadocDocletOptions).addStringOption("Xdoclint:all,-missing", "-quiet")
}
