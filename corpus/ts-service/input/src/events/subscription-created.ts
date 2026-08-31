/** Emitted by SubscriptionService, consumed by InvoiceService. */
export interface SubscriptionCreated {
  subscriptionId: string;
  customerId: string;
  occurredAt: Date;
}
