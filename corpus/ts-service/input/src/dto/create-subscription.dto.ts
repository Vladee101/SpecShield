import { PlanTier } from "../domain/plan-tier";

/** Payload accepted by BillingApi on POST /subscriptions. */
export interface CreateSubscriptionDto {
  customerId: string;
  planTier: PlanTier;
}

/** Projection returned to the Vantor web console. */
export interface InvoiceSummaryDto {
  invoiceId: string;
  customerId: string;
  amountCents: number;
}
