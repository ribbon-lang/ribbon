package ribbon.cli

object Constants {
	private val ribbonPackage = ClassLoader.getSystemClassLoader().getDefinedPackage("ribbon")
	private val specVer = ribbonPackage.getSpecificationVersion()
	private val implVer = ribbonPackage.getImplementationVersion()
}
