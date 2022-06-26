package ribbon.parser

import ribbon.lexer.Token

sealed class Expr

data class Identifier(
	public val name: String
) : Expr() {
	override fun toString(): String = name
}

data class Integer(
	public val value: Int
) : Expr() {
	override fun toString(): String = value.toString()
}

data class BinaryOp(
	public val lhs: Expr,
	public val op: Token,
	public val rhs: Expr
) : Expr() {
	override fun toString(): String = "(%s %s %s)".format(lhs, op.lexeme, rhs)
}
