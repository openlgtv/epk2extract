#!/bin/bash
function my_indent() {
	file="$1"
	indent \
		--linux-style \
		--use-tabs \
		--tab-size4 \
		--indent-level4 \
		--preprocessor-indentation4 \
		--else-endif-column0 \
		--braces-on-if-line \
		--braces-on-func-def-line \
		--braces-on-struct-decl-line \
		--line-length0 \
			"$file"
}

if [ -z "$1" ]; then
	dirs="src include"
elif [ -d "$1" ]; then
	dirs="$1"
elif [ -f "$1" ]; then
	echo "Reindenting ${1}..."
	my_indent "$1"
	exit 0
fi

for file in `find src include -type f -name "*.c" -or -name "*.cpp" -or -name "*.h"`; do
	echo "Reindenting ${file}..."
	my_indent "$file"
done
exit 0
