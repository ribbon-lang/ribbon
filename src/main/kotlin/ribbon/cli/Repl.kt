package ribbon.cli

import ribbon.evaluator.Evaluator
import ribbon.lexer.Lexer
import ribbon.parser.Parser
import ribbon.reader.Reader

object Repl {
	fun run() {
		val evaluator = Evaluator()
		println(Constants.REPL_WELCOME_MSG)

		while (true) {
			print(Constants.REPL_PROMPT)

			val input = readlnOrNull()
			if (input == null) break

			when (input) {
				Constants.REPL_HELP_CMD -> println(Constants.REPL_HELP_MSG)
				Constants.REPL_QUIT_CMD -> break
				else -> {
					val expr = Parser(Lexer(Reader(input))).parseExpr()
					println(evaluator.evaluateExpr(expr))
				}
			}
		}
	}
}
