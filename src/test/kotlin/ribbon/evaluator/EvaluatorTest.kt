import kotlin.test.*

import ribbon.evaluator.*
import ribbon.lexer.*
import ribbon.parser.*
import ribbon.reader.*

class EvaluatorTest {
	private fun makeExpr(input: String): Expr = Parser(Lexer(Reader(input.trimMargin()))).parseExpr()

	@Test
	fun testArithmeticExpression() {
		val evaluator = Evaluator()

		var expr = makeExpr("1 + 2")
		assertEquals(3, evaluator.evaluateExpr(expr))

		expr = makeExpr("3 - 9 / 1 * 0")
		assertEquals(3, evaluator.evaluateExpr(expr))

		expr = makeExpr("6 ** 3 ** 0")
		assertEquals(6, evaluator.evaluateExpr(expr))
	}

	@Test
	fun testArithmeticExpressionWithVariables() {
		val evaluator = Evaluator()

		var expr = makeExpr("a = 1 + 2")
		assertEquals(3, evaluator.evaluateExpr(expr))

		expr = makeExpr("a * 100")
		assertEquals(300, evaluator.evaluateExpr(expr))

		expr = makeExpr("(a - 1) ** a ** (a - 1)")
		assertEquals(512, evaluator.evaluateExpr(expr))

		expr = makeExpr("b = a")
		assertEquals(3, evaluator.evaluateExpr(expr))

		expr = makeExpr("b = (b + 3) ** a")
		assertEquals(216, evaluator.evaluateExpr(expr))

		expr = makeExpr("b")
		assertEquals(216, evaluator.evaluateExpr(expr))
	}
}
