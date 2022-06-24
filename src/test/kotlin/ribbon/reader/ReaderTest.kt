import kotlin.test.*

import ribbon.reader.*

class ReaderTest {
	private fun assertReaderOutput(output: List<Triple<Char, Int, Int>>, reader: Reader) {
		output.forEach {
			val (char, line, col) = it
			assertEquals(char, reader.peek())
			assertEquals(Pair(line, col), reader.pos())
			reader.next()
		}

		assertEquals(Char.MIN_VALUE, reader.peek())
	}

	@Test
	fun testEmptyReader() {
		val reader = Reader("")
		assertReaderOutput(listOf(), reader)
	}

	@Test
	fun testOneLineInput() {
		var reader = Reader("""
			|abc
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('c', 1, 2)
		), reader)

		reader = Reader("""
			|ab
			|
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('\n', 1, 2)
		), reader)
	}

	@Test
	fun testOneLineInputWithSpaces() {
		var reader = Reader("""
			| a b
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple(' ', 1, 2),
			Triple('b', 1, 3)
		), reader)

		reader = Reader("""
			| a b
			|
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple(' ', 1, 2),
			Triple('b', 1, 3),
			Triple('\n', 1, 4)
		), reader)
	}

	@Test
	fun testMultipleLinesInput() {
		val reader = Reader("""
			|ab
			|c
			|
			|d
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('\n', 1, 2),
			Triple('c', 2, 0),
			Triple('\n', 2, 1),
			Triple('\n', 3, 0),
			Triple('d', 4, 0)
		), reader)
	}

	@Test
	fun testMultipleLinesInputWithSpaces() {
		val reader = Reader("""
			| ab
			|c
			|
			|  d
			| e
			|
		""".trimMargin())

		assertReaderOutput(listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple('b', 1, 2),
			Triple('\n', 1, 3),
			Triple('c', 2, 0),
			Triple('\n', 2, 1),
			Triple('\n', 3, 0),
			Triple(' ', 4, 0),
			Triple(' ', 4, 1),
			Triple('d', 4, 2),
			Triple('\n', 4, 3),
			Triple(' ', 5, 0),
			Triple('e', 5, 1),
			Triple('\n', 5, 2)
		), reader)
	}
}
