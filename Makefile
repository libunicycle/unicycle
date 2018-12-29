# SPDX-License-Identifier: MIT

app.elf=out/app.elf

.PHONY: $(app.elf)

$(app.elf):
	shog

gdb:
	@gdb "$(app.elf)" -ex "target remote :1234"

config:
	@KCONFIG_CONFIG=.config mconf -s Kconfig

format-code:
	find . -path ./third_party -prune -o -path ./out -prune -o -path ./test/acutest -prune -o -path ./app/memcached/memcached -prune -o \( -iname \*.h -o -iname \*.c \) -exec clang-format -i -style=file {} +

update-regmap:
	find . -name *.regs -exec sh -c "./scripts/gen_regmap.rb {}; clang-format -i -style=file {}.h" \;
