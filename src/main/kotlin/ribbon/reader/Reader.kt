package ribbon.reader

typealias Position = Pair<Int, Int>

class Reader(private val input: String) {
	private var index = 0
	private var lineNum = 1
	private var colNum = 0

	fun pos(): Position = Pair(lineNum, colNum)

	fun peek(): Char = if (index < input.length) input[index] else Char.MIN_VALUE

	fun next() {
		if (peek() == '\n') {
			lineNum++
			colNum = 0
		} else {
			colNum++
		}

		index++
	}
}
