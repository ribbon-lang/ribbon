import org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL

version = "0.0.0"

plugins {
	kotlin("jvm") version "1.7.0"
	application
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

tasks.test {
	useJUnitPlatform()
	testLogging.exceptionFormat = FULL
	testLogging.showStackTraces = false
}
