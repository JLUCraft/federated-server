plugins { java }
group = "com.jlucraft"
version = "0.1.0"
repositories {
    mavenCentral()
    maven("https://repo.papermc.io/repository/maven-public/")
}
dependencies { compileOnly("io.papermc.paper:paper-api:26.3.build.32-alpha") }
java { toolchain.languageVersion.set(JavaLanguageVersion.of(25)) }
