package ribbon.cli

object Repl {
	fun run() {
		println(Constants.REPL_WELCOME_MSG)

		while (true) {
			print(Constants.REPL_PROMPT)

			val input = readlnOrNull()
			if (input == null) break

			when (input) {
				Constants.REPL_HELP_CMD -> println(Constants.REPL_HELP_MSG)
				Constants.REPL_QUIT_CMD -> break
				input -> println("You said: $input")
			}
		}
	}
}
