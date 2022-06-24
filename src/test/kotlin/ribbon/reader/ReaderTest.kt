import kotlin.test.*

import ribbon.reader.*

class ReaderTest {
	private fun assertReaderOutput(reader: Reader, output: List<Triple<Char, Int, Int>>) {
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
		assertReaderOutput(reader, listOf())
	}

	@Test
	fun testOneLineInput() {
		var reader = Reader("""
			|abc
		""".trimMargin())

		assertReaderOutput(reader, listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('c', 1, 2)
		))

		reader = Reader("""
			|ab
			|
		""".trimMargin())

		assertReaderOutput(reader, listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('\n', 1, 2)
		))
	}

	@Test
	fun testOneLineInputWithSpaces() {
		var reader = Reader("""
			| a b
		""".trimMargin())

		assertReaderOutput(reader, listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple(' ', 1, 2),
			Triple('b', 1, 3)
		))

		reader = Reader("""
			| a b
			|
		""".trimMargin())

		assertReaderOutput(reader, listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple(' ', 1, 2),
			Triple('b', 1, 3),
			Triple('\n', 1, 4)
		))
	}

	@Test
	fun testMultipleLinesInput() {
		val reader = Reader("""
			|ab
			|c
			|
			|d
		""".trimMargin())

		assertReaderOutput(reader, listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('\n', 1, 2),
			Triple('c', 2, 0),
			Triple('\n', 2, 1),
			Triple('\n', 3, 0),
			Triple('d', 4, 0)
		))
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

		assertReaderOutput(reader, listOf(
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
		))
	}
}
