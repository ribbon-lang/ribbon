package ribbon.evaluator

import kotlin.math.pow

import ribbon.lexer.TokenKind
import ribbon.parser.BinaryOp
import ribbon.parser.Expr
import ribbon.parser.Identifier
import ribbon.parser.Integer

class Evaluator {
	private var variables: MutableMap<String, Int> = mutableMapOf()

	fun evaluateExpr(expr: Expr): Int {
		return when (expr) {
			is Integer -> expr.value
			is Identifier -> variables.get(expr.name)!!
			is BinaryOp -> {
				val rhs = evaluateExpr(expr.rhs)
				if (expr.op.kind == TokenKind.Equal) {
					val ident = expr.lhs as Identifier
					variables.put(ident.name, rhs)
					return rhs
				}

				val lhs = evaluateExpr(expr.lhs)
				when (expr.op.kind) {
					TokenKind.Plus -> lhs + rhs
					TokenKind.Minus -> lhs - rhs
					TokenKind.Asterisk -> lhs * rhs
					TokenKind.Slash -> lhs / rhs
					TokenKind.DblAsterisk -> lhs.toDouble().pow(rhs).toInt()

					// this will eventually error
					else -> 0
				}
			}
		}
	}
}
