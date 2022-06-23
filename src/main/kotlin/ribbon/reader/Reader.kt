package ribbon.reader

typealias Position = Pair<Int, Int>

class Reader(private val input: String) {
	private var index = 0
	private var lineNum = 1
	private var colNum = -1

	fun next(): Pair<Char, Position>? {
		if (index >= input.length) return null

		val char = input[index++]
		val pos = Pair(lineNum, ++colNum)

		if (char == '\n') {
			lineNum++
			colNum = -1
		}

		return Pair(char, pos)
	}
}
