#!/bin/bash
set -e

# Script to create Kubernetes secrets for microservices
# Usage: ./scripts/create-secrets.sh [environment]

ENVIRONMENT="${1:-default}"
NAMESPACE="platform"

echo "🔐 Creating secrets for environment: $ENVIRONMENT"

# Prompt for secrets (in production, use Azure Key Vault)
read -sp "PostgreSQL Password: " POSTGRES_PASSWORD
echo
read -sp "Redis Password: " REDIS_PASSWORD
echo
read -sp "RabbitMQ Password: " RABBITMQ_PASSWORD
echo
read -sp "JWT Secret Key: " JWT_SECRET
echo
read -p "SMTP Host: " SMTP_HOST
read -sp "SMTP Password: " SMTP_PASSWORD
echo

# PostgreSQL connection string
POSTGRES_CONNECTION="Host=postgres-ha-postgresql-ha-pgpool.infrastructure.svc.cluster.local;Port=5432;Database=platformdb;Username=postgres;Password=${POSTGRES_PASSWORD}"

# Redis connection
REDIS_CONNECTION="redis:6379,password=${REDIS_PASSWORD}"

# RabbitMQ connection
RABBITMQ_CONNECTION="amqp://admin:${RABBITMQ_PASSWORD}@rabbitmq.infrastructure.svc.cluster.local:5672"

# Identity service secrets
echo "📦 Creating identity-secrets..."
kubectl create secret generic identity-secrets \
    --from-literal=database-connection="$POSTGRES_CONNECTION" \
    --from-literal=redis-connection="$REDIS_CONNECTION" \
    --from-literal=jwt-secret="$JWT_SECRET" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# Payment service secrets
echo "📦 Creating payment-secrets..."
kubectl create secret generic payment-secrets \
    --from-literal=database-connection="$POSTGRES_CONNECTION" \
    --from-literal=rabbitmq-connection="$RABBITMQ_CONNECTION" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

# Notification service secrets
echo "📦 Creating notification-secrets..."
kubectl create secret generic notification-secrets \
    --from-literal=rabbitmq-connection="$RABBITMQ_CONNECTION" \
    --from-literal=smtp-host="$SMTP_HOST" \
    --from-literal=smtp-password="$SMTP_PASSWORD" \
    --namespace="$NAMESPACE" \
    --dry-run=client -o yaml | kubectl apply -f -

echo "✅ Secrets created successfully!"

