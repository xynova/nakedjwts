WORKING_DIR := $(shell pwd)
LOCAL_TAG = local/nakedjwts
export DOCKER_BUILDKIT=1

.PHONY: docker-build docker-save docker-dev docker-test
.DEFAULT_GOAL := docker-build


docker-build:: ## Build the image for local testing
		@echo Building ${LOCAL_TAG}
		@docker build \
			-t ${LOCAL_TAG} ${WORKING_DIR}

# A help target including self-documenting targets (see the awk statement)
define HELP_TEXT
Usage: make [TARGET]... [MAKEVAR1=SOMETHING]...

Available targets:
endef
export HELP_TEXT
help: ## This help target
	@echo
	@echo "$$HELP_TEXT"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / \
		{printf "\033[36m%-30s\033[0m  %s\n", $$1, $$2}' $(MAKEFILE_LIST)
