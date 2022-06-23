import kotlin.test.*

import ribbon.reader.*

class ReaderTest {
	@Test
	fun testEmptyReader() {
		val reader = Reader("")
		assertNull(reader.next())
	}

	@Test
	fun testOneLineInput() {
		var reader = Reader("""
			|abc
		""".trimMargin())

		listOf(
			Pair('a', Pair(1, 0)),
			Pair('b', Pair(1, 1)),
			Pair('c', Pair(1, 2)),
			null
		).forEach { assertEquals(it, reader.next()) }

		reader = Reader("""
			|ab
			|
		""".trimMargin())

		listOf(
			Pair('a', Pair(1, 0)),
			Pair('b', Pair(1, 1)),
			Pair('\n', Pair(1, 2)),
			null
		).forEach { assertEquals(it, reader.next()) }
	}

	@Test
	fun testOneLineInputWithSpaces() {
		val reader = Reader("""
			| a b
		""".trimMargin())

		listOf(
			Pair(' ', Pair(1, 0)),
			Pair('a', Pair(1, 1)),
			Pair(' ', Pair(1, 2)),
			Pair('b', Pair(1, 3)),
			null
		).forEach { assertEquals(it, reader.next()) }
	}

	@Test
	fun testMultipleLinesInput() {
		val reader = Reader("""
			|ab
			|c
			|
			|d
		""".trimMargin())

		listOf(
			Pair('a', Pair(1, 0)),
			Pair('b', Pair(1, 1)),
			Pair('\n', Pair(1, 2)),
			Pair('c', Pair(2, 0)),
			Pair('\n', Pair(2, 1)),
			Pair('\n', Pair(3, 0)),
			Pair('d', Pair(4, 0)),
			null
		).forEach { assertEquals(it, reader.next()) }
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

		listOf(
			Pair(' ', Pair(1, 0)),
			Pair('a', Pair(1, 1)),
			Pair('b', Pair(1, 2)),
			Pair('\n', Pair(1, 3)),
			Pair('c', Pair(2, 0)),
			Pair('\n', Pair(2, 1)),
			Pair('\n', Pair(3, 0)),
			Pair(' ', Pair(4, 0)),
			Pair(' ', Pair(4, 1)),
			Pair('d', Pair(4, 2)),
			Pair('\n', Pair(4, 3)),
			Pair(' ', Pair(5, 0)),
			Pair('e', Pair(5, 1)),
			Pair('\n', Pair(5, 2)),
			null
		).forEach { assertEquals(it, reader.next()) }
	}
}
