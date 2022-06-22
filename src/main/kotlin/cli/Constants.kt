package ribbon.cli

object Constants {
	private val ribbonPackage = ClassLoader.getSystemClassLoader().getDefinedPackage("ribbon")
	private val specVer = ribbonPackage.getSpecificationVersion()
	private val implVer = ribbonPackage.getImplementationVersion()

	const val REPL_PROMPT = "> "

	const val REPL_HELP_CMD = ":h"
	const val REPL_QUIT_CMD = ":q"

	val REPL_HELP_MSG = AsciiBox(
		"Commands",
		":h         Show this message",
		":q         Quit"
	)

	val REPL_WELCOME_MSG = AsciiBox(
		"Ribbon v$specVer",
		"(build $implVer)",
		"Type \":h\" for more information."
	)
}
