# Billing Platform — Product Requirements

## Overview

Vantor operates a subscription billing platform for freight brokers. The largest
account, Meridian Freight, processes roughly 40,000 invoices per month through
the platform.

Card capture and payouts are handled by Paylane, our payment service provider.
Vantor never stores card numbers directly.

## Services

The billing domain is split across three services:

- **SubscriptionService** owns the lifecycle of a CustomerSubscription, from
  trial through cancellation.
- **InvoiceService** generates monthly invoices and reconciles them against
  Paylane settlement reports.
- **NotificationService** delivers dunning email on failed payment.

SubscriptionService publishes a SubscriptionCreated event that InvoiceService
consumes. InvoiceService publishes InvoiceIssued in turn.

## Plan tiers

Every CustomerSubscription carries a PlanTier. Meridian Freight is on the
Enterprise tier, which waives the per-invoice fee above 25,000 invoices.

## API surface

External integrators reach the platform through BillingApi, documented as an
OpenAPI 3.1 specification. The two endpoints in scope for this release are
`POST /subscriptions` and `GET /invoices/{invoiceId}`.

BillingApi runs behind billing.vantor.internal and is not exposed publicly.
Clients resolve it through VANTOR_BILLING_URL.

## Constraints

- Data lives in Postgres. The schema is owned by the billing team.
- The web console is React and TypeScript; the services are Node and Express.
- Paylane webhooks are authenticated with PAYLANE_WEBHOOK_SECRET.

## Out of scope

Multi-currency invoicing. Meridian Freight has asked for it, but the Paylane
contract does not cover settlement outside USD until next year.
