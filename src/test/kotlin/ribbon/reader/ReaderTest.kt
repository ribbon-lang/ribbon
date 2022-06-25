import kotlin.test.*

import ribbon.reader.*

class ReaderTest {
	private fun makeReader(input: String): Reader = Reader(input.trimMargin())

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
		val reader = makeReader("")
		assertReaderOutput(reader, listOf())
	}

	@Test
	fun testOneLineInput() {
		var reader = makeReader("""
			|abc
		""")

		assertReaderOutput(reader, listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('c', 1, 2)
		))

		reader = makeReader("""
			|ab
			|
		""")

		assertReaderOutput(reader, listOf(
			Triple('a', 1, 0),
			Triple('b', 1, 1),
			Triple('\n', 1, 2)
		))
	}

	@Test
	fun testOneLineInputWithSpaces() {
		var reader = makeReader("""
			| a b
		""")

		assertReaderOutput(reader, listOf(
			Triple(' ', 1, 0),
			Triple('a', 1, 1),
			Triple(' ', 1, 2),
			Triple('b', 1, 3)
		))

		reader = makeReader("""
			| a b
			|
		""")

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
		val reader = makeReader("""
			|ab
			|c
			|
			|d
		""")

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
		val reader = makeReader("""
			| ab
			|c
			|
			|  d
			| e
			|
		""")

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
