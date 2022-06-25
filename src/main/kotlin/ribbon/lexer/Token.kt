package ribbon.lexer

import ribbon.reader.Position

enum class TokenKind {
	Equal,
	Plus,
	Minus,
	Asterisk,
	Slash,
	DblAsterisk,

	LParen,
	RParen,

	Identifier,
	Integer,
	Eof
}

data class Token(
	val kind: TokenKind = TokenKind.Eof,
	val lexeme: String = "",
	val pos: Position = Pair(0, 0)
)
