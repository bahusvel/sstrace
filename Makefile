install: cmd/sstrace/main.go
	go build -o sstrace cmd/sstrace/*.go

build_test: static.c
	gcc static.c -o static

dump_test: build_test
	objdump -d static > static.S

extract: build_test
	objcopy -O binary --only-section=.text static static.text

reference: extract
	objdump -b binary -m i386:x86-64 -D static.text > static_text.S

run: install dump_test reference
	./sstrace static.text
