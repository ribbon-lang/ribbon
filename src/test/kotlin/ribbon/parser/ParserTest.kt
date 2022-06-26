import kotlin.test.*

import ribbon.lexer.*
import ribbon.parser.*
import ribbon.reader.*

class ParserTest {
	private fun makeParser(input: String): Parser = Parser(Lexer(Reader(input.trimMargin())))

	private fun assertParserOutput(parser: Parser, output: String) {
		assertEquals(output, parser.parseExpr().toString())
	}

	@Test
	fun testSimpleNumerals() {
		var parser = makeParser("6")
		assertParserOutput(parser, "6")

		parser = makeParser("-3")
		assertParserOutput(parser, "-3")

		parser = makeParser(" -9033")
		assertParserOutput(parser, "-9033")
	}

	@Test
	fun testArithmeticExpression() {
		var parser = makeParser("-3 ** 6")
		assertParserOutput(parser, "(-3 ** 6)")

		parser = makeParser("3 ** -6 ** 0")
		assertParserOutput(parser, "(3 ** (-6 ** 0))")

		parser = makeParser("9 * 0 + 3")
		assertParserOutput(parser, "((9 * 0) + 3)")

		parser = makeParser("9 - 0 / 3")
		assertParserOutput(parser, "(9 - (0 / 3))")

		parser = makeParser("(9 - 0) / 3")
		assertParserOutput(parser, "((9 - 0) / 3)")

		parser = makeParser("48 - (0 / (9 - 33) + 15) - 12 ** -6")
		assertParserOutput(parser, "((48 - ((0 / (9 - 33)) + 15)) - (12 ** -6))")
	}

	@Test
	fun testSourceCode() {
		var parser = makeParser("a = 3")
		assertParserOutput(parser, "(a = 3)")

		parser = makeParser("a = -3/(6 - 0)")
		assertParserOutput(parser, "(a = (-3 / (6 - 0)))")

		parser = makeParser("b = 999 - (333)")
		assertParserOutput(parser, "(b = (999 - 333))")

		parser = makeParser("a=a+15-36*a")
		assertParserOutput(parser, "(a = ((a + 15) - (36 * a)))")
	}
}
