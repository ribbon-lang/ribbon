package ribbon.cli

class AsciiBox(vararg args: String) {
	val lines = args.asList()
	val longestLine = lines.maxByOrNull<String, Int> { it.length }
	val width = longestLine?.length ?: 0

	override fun toString(): String {
		val paddedLines = lines.map {
			"%s %s %s".format("│", it.padEnd(width), "│")
		}

		return buildString {
			appendLine("%s%s%s".format("┌", "─".repeat(width + 2), "┐"))

			for (line in paddedLines) {
				appendLine(line)
			}

			append("%s%s%s".format("└", "─".repeat(width + 2), "┘"))
		}
	}
}
