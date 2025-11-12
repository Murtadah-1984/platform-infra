.PHONY: help install sync diff lint clean

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install: ## Install all components using helmfile
	helmfile sync

sync: ## Sync all components
	helmfile sync

diff: ## Show diff of changes
	helmfile diff

lint: ## Lint helm charts
	helm lint charts/identity
	helm lint charts/payment
	helm lint charts/notification

clean: ## Remove all components
	helmfile destroy

deploy-dev: ## Deploy to dev environment
	helmfile -e dev sync

deploy-staging: ## Deploy to staging environment
	helmfile -e staging sync

deploy-prod: ## Deploy to production environment
	helmfile -e production sync

