package ribbon.parser

import ribbon.lexer.Lexer
import ribbon.lexer.Token
import ribbon.lexer.TokenKind

class Parser(private val lexer: Lexer) {
	private fun precedence(kind: TokenKind): Int {
		return when (kind) {
			TokenKind.Plus -> 18
			TokenKind.Minus -> 18
			TokenKind.Asterisk -> 21
			TokenKind.Slash -> 21
			TokenKind.DblAsterisk -> 24
			TokenKind.Equal -> 3
			else -> 0
		}
	}

	fun parseExpr(prec: Int = 0): Expr {
		val token = lexer.peek()
		var left: Expr

		if (token.kind == TokenKind.Identifier) {
			left = Identifier(token.lexeme)
		} else if (token.kind == TokenKind.LParen) {
			lexer.next()
			left = parseExpr(0)
		} else if (token.kind == TokenKind.Minus) {
			lexer.next()
			val num = lexer.peek().lexeme.toInt()
			left = Integer(-num)
		} else {
			left = Integer(token.lexeme.toInt())
		}

		lexer.next()
		while (true) {
			val op = lexer.peek()

			// rewrite this better with associativity in mind
			if (op.kind == TokenKind.DblAsterisk && precedence(op.kind) < prec) break
			if (op.kind != TokenKind.DblAsterisk && precedence(op.kind) <= prec) break

			lexer.next()
			left = BinaryOp(left, op, parseExpr(precedence(op.kind)))
		}

		return left
	}
}
