package ribbon.reader

typealias Position = Pair<Int, Int>

class Reader(private val input: String) {
	private var index = 0
	private var lineNum = 1
	private var colNum = 0

	fun next(): Pair<Char, Position> {
		if (index == input.length) {
			return Pair(Char.MIN_VALUE, Pair(lineNum, colNum))
		}

		val char = input[index++]
		val pos = Pair(lineNum, colNum++)

		if (char == '\n') {
			lineNum++
			colNum = 0
		}

		return Pair(char, pos)
	}
}
