import kotlin.test.*

import ribbon.cli.*

class AsciiBoxTest {
	@Test
	fun testEmptyAsciiBox() {
		val expected = """
			┌──┐
			└──┘
		""".trimIndent()

		val actual = AsciiBox().toString()
		assertEquals(expected, actual)
	}

	@Test
	fun testAsciiBoxWithOneLine() {
		val expected = """
			┌──────┐
			│ test │
			└──────┘
		""".trimIndent()

		val actual = AsciiBox("test").toString()
		assertEquals(expected, actual)
	}

	@Test
	fun testAsciiBoxWithMultipleLines() {
		val expected = """
			┌───────┐
			│ 123   │
			│ 45678 │
			│ 9     │
			└───────┘
		""".trimIndent()

		val actual = AsciiBox("123", "45678", "9").toString()
		assertEquals(expected, actual)
	}
}
