

native:
	echo "Building native"
	cargo build --release --features udp

ubuntu-22.04:
	@echo "Building ubuntu-22.04"
	docker build -t ubuntu22 -f ubuntu22.Dockerfile .
	docker run --rm \
		-v "$(shell pwd)"/target/multi-build/ubuntu-22.04-udp:/output \
		ubuntu22 \
		sh -c "cp -rv /app/target/release/* /output/ && echo 'Files copied:' && ls -lh /output"