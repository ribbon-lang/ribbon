import com.github.stefanbirkner.systemlambda.SystemLambda.*
import kotlin.test.*

import ribbon.*
import ribbon.cli.*

class ReplTest {
	@Test
	fun testReplWithoutInput() {
		withTextFromSystemIn().execute {
			val expected = buildString {
				appendLine(Constants.REPL_WELCOME_MSG)
				append(Constants.REPL_PROMPT)
			}

			val actual = tapSystemOut {
				main()
			}

			assertEquals(expected, actual)
		}
	}

	@Test
	fun testHelpCommand() {
		withTextFromSystemIn(Constants.REPL_HELP_CMD).execute {
			val expected = buildString {
				appendLine(Constants.REPL_WELCOME_MSG)
				append(Constants.REPL_PROMPT)
				appendLine(Constants.REPL_HELP_MSG)
				append(Constants.REPL_PROMPT)
			}

			val actual = tapSystemOut {
				main()
			}

			assertEquals(expected, actual)
		}
	}

	@Test
	fun testQuitCommand() {
		withTextFromSystemIn(Constants.REPL_QUIT_CMD, Constants.REPL_HELP_CMD).execute {
			val expected = buildString {
				appendLine(Constants.REPL_WELCOME_MSG)
				append(Constants.REPL_PROMPT)
			}

			val actual = tapSystemOut {
				main()
			}

			assertEquals(expected, actual)
		}
	}

	@Test
	fun testMultipleCommands() {
		withTextFromSystemIn(Constants.REPL_HELP_CMD, Constants.REPL_QUIT_CMD, Constants.REPL_HELP_CMD).execute {
			val expected = buildString {
				appendLine(Constants.REPL_WELCOME_MSG)
				append(Constants.REPL_PROMPT)
				appendLine(Constants.REPL_HELP_MSG)
				append(Constants.REPL_PROMPT)
			}

			val actual = tapSystemOut {
				main()
			}

			assertEquals(expected, actual)
		}
	}

	/*
	@Test
	fun testNonCommandsEchoed() {
		withTextFromSystemIn("Hello, Ribbon!").execute {
			val expected = buildString {
				appendLine(Constants.REPL_WELCOME_MSG)
				append(Constants.REPL_PROMPT)
				appendLine("You said: Hello, Ribbon!")
				append(Constants.REPL_PROMPT)
			}

			val actual = tapSystemOut {
				main()
			}

			assertEquals(expected, actual)
		}
	}
	*/
}
