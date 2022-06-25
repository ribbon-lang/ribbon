package ribbon.lexer

import ribbon.reader.Position
import ribbon.reader.Reader

class Lexer(private val reader: Reader) {
	private var token: Token = Token()
	private var pos: Position = token.pos

	init {
		next()
	}

	private fun isIdentifierStart(char: Char): Boolean = char.isLetter() || char == '_'

	private fun isIdentifierPart(char: Char): Boolean = isIdentifierStart(char) || char.isDigit() || char == '\''

	private fun isIntegerStart(char: Char): Boolean = char in '0'..'9'

	private fun lexIdentifier() {
		val lexeme = buildString {
			while (isIdentifierPart(reader.peek())) {
				append(reader.peek())
				reader.next()
			}
		}

		token = Token(TokenKind.Identifier, lexeme, pos)
	}

	private fun lexInteger() {
		val lexeme = buildString {
			while (reader.peek() in '0'..'9') {
				append(reader.peek())
				reader.next()
			}
		}

		token = Token(TokenKind.Integer, lexeme, pos)
	}

	private fun lexSymbol(kind: TokenKind, lexeme: String) {
		repeat(lexeme.length) { reader.next() }
		token = Token(kind, lexeme, pos)
	}

	fun peek(): Token = token

	fun next() {
		while (reader.peek().isWhitespace()) reader.next()
		pos = reader.pos()

		val char = reader.peek()
		if (isIdentifierStart(char)) {
			lexIdentifier()
			return
		}

		if (isIntegerStart(char)) {
			lexInteger()
			return
		}

		when (char) {
			'=' -> lexSymbol(TokenKind.Equal, "=")
			'+' -> lexSymbol(TokenKind.Plus, "+")
			'-' -> lexSymbol(TokenKind.Minus, "-")
			'*' -> {
				if (reader.hasPrefix("**")) lexSymbol(TokenKind.DblAsterisk, "**")
				else lexSymbol(TokenKind.Asterisk, "*")
			}
			'/' -> lexSymbol(TokenKind.Slash, "/")
			'(' -> lexSymbol(TokenKind.LParen, "(")
			')' -> lexSymbol(TokenKind.RParen, ")")
			';' -> lexSymbol(TokenKind.Semicolon, ";")
			else -> lexSymbol(TokenKind.Eof, "")
		}
	}
}
