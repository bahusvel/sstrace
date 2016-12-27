static_go: static_go.go
	go build -o static_go static_go.go

go_extract: static_go
	objcopy -O binary --only-section=.text static_go static_go.text

install: cmd/sstrace/main.go
	go build -o sstrace cmd/sstrace/*.go

build_test: static.c
	gcc static.c -o static

dump_test: build_test
	objdump -d static > static.S

extract: build_test
	objcopy -O binary --only-section=.text static static.text

run: install dump_test go_extract extract
	./sstrace static_go.text
