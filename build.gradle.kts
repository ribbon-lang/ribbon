import org.codehaus.groovy.runtime.ProcessGroovyMethods
import org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL

version = "0.1.0"

plugins {
	kotlin("jvm") version "1.7.0"
	application
	jacoco
	id("com.github.johnrengelman.shadow") version "7.1.2"
}

repositories {
	mavenCentral()
}

dependencies {
	testImplementation(kotlin("test"))
}

application {
	mainClass.set("ribbon.MainKt")
}

tasks {
	withType<Jar> {
		val process = ProcessGroovyMethods.execute("git rev-parse --short HEAD")
		val hash = ProcessGroovyMethods.getText(process).trim()

		manifest.attributes["Specification-Version"] = archiveVersion
		manifest.attributes["Implementation-Version"] = hash
	}

	test {
		useJUnitPlatform()
		testLogging.exceptionFormat = FULL
		testLogging.showStackTraces = false
	}
}
