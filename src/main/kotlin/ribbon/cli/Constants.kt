package ribbon.cli

import ribbon.BuildConfig

object Constants {
	const val REPL_PROMPT = "> "

	const val REPL_HELP_CMD = ":h"
	const val REPL_QUIT_CMD = ":q"

	val REPL_HELP_MSG = AsciiBox(
		"Commands",
		":h         Show this message",
		":q         Quit"
	)

	val REPL_WELCOME_MSG = AsciiBox(
		"Ribbon v${BuildConfig.RIBBON_VERSION}",
		"(build ${BuildConfig.RIBBON_BUILD})",
		"Type \":h\" for more information."
	)
}
