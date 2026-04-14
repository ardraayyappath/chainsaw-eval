KEYS_DIR  := keys
PRIVKEY   := $(KEYS_DIR)/eval_key
PUBKEY    := $(KEYS_DIR)/eval_key.pub
# target/ build context needs the public key present
TARGET_PUBKEY := target/eval_key.pub

.PHONY: keys build up down logs clean

## Generate SSH key pair (run once before first build).
keys: $(TARGET_PUBKEY)

$(TARGET_PUBKEY): $(PUBKEY)
	cp $(PUBKEY) $(TARGET_PUBKEY)

$(PUBKEY):
	mkdir -p $(KEYS_DIR)
	ssh-keygen -t ed25519 -N "" -f $(PRIVKEY) -C "chainsaw-eval"
	@echo "Keys written to $(KEYS_DIR)/"

## Build the target image (requires keys).
build: $(TARGET_PUBKEY)
	docker compose build

## Start all scenario targets in the background.
up: $(TARGET_PUBKEY)
	docker compose up -d

## Stop and remove containers.
down:
	docker compose down

## Follow logs for all containers.
logs:
	docker compose logs -f

## Tear down containers and volumes; remove generated key from build context.
clean:
	docker compose down -v
	rm -f $(TARGET_PUBKEY)
