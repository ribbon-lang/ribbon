import org.codehaus.groovy.runtime.ProcessGroovyMethods
import org.gradle.api.tasks.testing.logging.TestExceptionFormat.*
import org.gradle.api.tasks.testing.logging.TestLogEvent.*

version = "0.1.0"

plugins {
	kotlin("jvm") version "1.7.0"
	application
	jacoco
	id("com.github.johnrengelman.shadow") version "7.1.2"
	id("com.github.gmazzo.buildconfig") version "3.1.0"
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

buildConfig {
	val process = ProcessGroovyMethods.execute("git rev-parse --short HEAD")
	val hash = ProcessGroovyMethods.getText(process).trim()

	packageName("ribbon")
	buildConfigField("String", "RIBBON_VERSION", "\"$version\"")
	buildConfigField("String", "RIBBON_BUILD", "\"$hash\"")
}

tasks {
	test {
		finalizedBy(jacocoTestReport)
		useJUnitPlatform()

		testLogging {
			events(FAILED, PASSED, SKIPPED)
			exceptionFormat = FULL
			showStackTraces = false
		}
	}
}
