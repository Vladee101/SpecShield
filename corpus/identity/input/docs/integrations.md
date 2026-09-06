# Vantor payments integration

Vantor is a freight billing platform. The commercial product is FreightLedger,
sold to carriers under the Haulwise brand.

## Money

Card payments go through Stripe, with Adyen as the fallback processor. Recurring
plans are billed through Chargebee.

## Everything else

Notifications go out via Twilio for SMS and SendGrid for email. Access tokens are
issued by Auth0. Errors land in Sentry and operational metrics in Datadog.

## Where it runs

The public API is served from api.vantor-freight.com and the operations console
from ops.vantor-freight.com.

## What it is made of

BillingService charges an invoice, CustomerSubscription describes the plan a
carrier is on, and the customer_subscription table holds the rows. A React front
end talks to Postgres through Prisma.
