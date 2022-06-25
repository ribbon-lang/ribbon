import kotlin.test.*

import ribbon.lexer.*
import ribbon.reader.*

class LexerTest {
	private fun makeLexer(input: String): Lexer = Lexer(Reader(input.trimMargin()))

	private fun assertLexerOutput(lexer: Lexer, output: List<Token>) {
		output.forEach {
			val (kind, lexeme, pos) = lexer.peek()
			assertEquals(it.kind, kind)
			assertEquals(it.lexeme, lexeme)
			assertEquals(it.pos, pos)
			lexer.next()
		}

		assertEquals(TokenKind.Eof, lexer.peek().kind)
	}

	@Test
	fun testEmptyLexer() {
		val lexer = makeLexer("")
		assertLexerOutput(lexer, listOf())
	}

	@Test
	fun testLexerWithIdentifierInput() {
		assertLexerOutput(makeLexer("a"), listOf(
			Token(TokenKind.Identifier, "a", Pair(1, 0))
		))

		assertLexerOutput(makeLexer("  ribbon 丝带  リボン"), listOf(
			Token(TokenKind.Identifier, "ribbon", Pair(1, 2)),
			Token(TokenKind.Identifier, "丝带", Pair(1, 9)),
			Token(TokenKind.Identifier, "リボン", Pair(1, 13))
		))

		assertLexerOutput(makeLexer("item0  item1 item2_item3 __item4 "), listOf(
			Token(TokenKind.Identifier, "item0", Pair(1, 0)),
			Token(TokenKind.Identifier, "item1", Pair(1, 7)),
			Token(TokenKind.Identifier, "item2_item3", Pair(1, 13)),
			Token(TokenKind.Identifier, "__item4", Pair(1, 25))
		))

		assertLexerOutput(makeLexer(" it isn't_ a' they_aren't"), listOf(
			Token(TokenKind.Identifier, "it", Pair(1, 1)),
			Token(TokenKind.Identifier, "isn't_", Pair(1, 4)),
			Token(TokenKind.Identifier, "a'", Pair(1, 11)),
			Token(TokenKind.Identifier, "they_aren't", Pair(1, 14))
		))
	}

	@Test
	fun testLexerWithIntegerInput() {
		assertLexerOutput(makeLexer("3"), listOf(
			Token(TokenKind.Integer, "3", Pair(1, 0))
		))

		assertLexerOutput(makeLexer(" 54  03 987 "), listOf(
			Token(TokenKind.Integer, "54", Pair(1, 1)),
			Token(TokenKind.Integer, "03", Pair(1, 5)),
			Token(TokenKind.Integer, "987", Pair(1, 8))
		))
	}

	@Test
	fun testLexerWithSymbolInput() {
		assertLexerOutput(makeLexer("*"), listOf(
			Token(TokenKind.Asterisk, "*", Pair(1, 0))
		))

		assertLexerOutput(makeLexer("+* -/"), listOf(
			Token(TokenKind.Plus, "+", Pair(1, 0)),
			Token(TokenKind.Asterisk, "*", Pair(1, 1)),
			Token(TokenKind.Minus, "-", Pair(1, 3)),
			Token(TokenKind.Slash, "/", Pair(1, 4))
		))

		assertLexerOutput(makeLexer("*** -="), listOf(
			Token(TokenKind.DblAsterisk, "**", Pair(1, 0)),
			Token(TokenKind.Asterisk, "*", Pair(1, 2)),
			Token(TokenKind.Minus, "-", Pair(1, 4)),
			Token(TokenKind.Equal, "=", Pair(1, 5))
		))

		assertLexerOutput(makeLexer(")  / (**)"), listOf(
			Token(TokenKind.RParen, ")", Pair(1, 0)),
			Token(TokenKind.Slash, "/", Pair(1, 3)),
			Token(TokenKind.LParen, "(", Pair(1, 5)),
			Token(TokenKind.DblAsterisk, "**", Pair(1, 6)),
			Token(TokenKind.RParen, ")", Pair(1, 8))
		))
	}

	@Test
	fun testLexerWithMixedInput() {
		var lexer = makeLexer("90f x++  y*=( z )  a=36b(/ ) =c")

		assertLexerOutput(lexer, listOf(
			Token(TokenKind.Integer, "90", Pair(1, 0)),
			Token(TokenKind.Identifier, "f", Pair(1, 2)),
			Token(TokenKind.Identifier, "x", Pair(1, 4)),
			Token(TokenKind.Plus, "+", Pair(1, 5)),
			Token(TokenKind.Plus, "+", Pair(1, 6)),
			Token(TokenKind.Identifier, "y", Pair(1, 9)),
			Token(TokenKind.Asterisk, "*", Pair(1, 10)),
			Token(TokenKind.Equal, "=", Pair(1, 11)),
			Token(TokenKind.LParen, "(", Pair(1, 12)),
			Token(TokenKind.Identifier, "z", Pair(1, 14)),
			Token(TokenKind.RParen, ")", Pair(1, 16)),
			Token(TokenKind.Identifier, "a", Pair(1, 19)),
			Token(TokenKind.Equal, "=", Pair(1, 20)),
			Token(TokenKind.Integer, "36", Pair(1, 21)),
			Token(TokenKind.Identifier, "b", Pair(1, 23)),
			Token(TokenKind.LParen, "(", Pair(1, 24)),
			Token(TokenKind.Slash, "/", Pair(1, 25)),
			Token(TokenKind.RParen, ")", Pair(1, 27)),
			Token(TokenKind.Equal, "=", Pair(1, 29)),
			Token(TokenKind.Identifier, "c", Pair(1, 30))
		))

		lexer = makeLexer("""
			|a = 3 * (0)
			|b = (9 - 45)**a
			|a+b / 3
		""")

		assertLexerOutput(lexer, listOf(
			Token(TokenKind.Identifier, "a", Pair(1, 0)),
			Token(TokenKind.Equal, "=", Pair(1, 2)),
			Token(TokenKind.Integer, "3", Pair(1, 4)),
			Token(TokenKind.Asterisk, "*", Pair(1, 6)),
			Token(TokenKind.LParen, "(", Pair(1, 8)),
			Token(TokenKind.Integer, "0", Pair(1, 9)),
			Token(TokenKind.RParen, ")", Pair(1, 10)),
			Token(TokenKind.Identifier, "b", Pair(2, 0)),
			Token(TokenKind.Equal, "=", Pair(2, 2)),
			Token(TokenKind.LParen, "(", Pair(2, 4)),
			Token(TokenKind.Integer, "9", Pair(2, 5)),
			Token(TokenKind.Minus, "-", Pair(2, 7)),
			Token(TokenKind.Integer, "45", Pair(2, 9)),
			Token(TokenKind.RParen, ")", Pair(2, 11)),
			Token(TokenKind.DblAsterisk, "**", Pair(2, 12)),
			Token(TokenKind.Identifier, "a", Pair(2, 14)),
			Token(TokenKind.Identifier, "a", Pair(3, 0)),
			Token(TokenKind.Plus, "+", Pair(3, 1)),
			Token(TokenKind.Identifier, "b", Pair(3, 2)),
			Token(TokenKind.Slash, "/", Pair(3, 4)),
			Token(TokenKind.Integer, "3", Pair(3, 6))
		))
	}
}
