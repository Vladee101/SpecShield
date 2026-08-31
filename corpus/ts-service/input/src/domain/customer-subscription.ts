import { PlanTier } from "./plan-tier";

/** Mirrors the customer_subscription table. */
export interface CustomerSubscription {
  subscriptionId: string;
  customerId: string;
  planTier: PlanTier;
  startedAt: Date;
}
