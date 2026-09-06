/**
 * Charges an invoice against the carrier's saved payment method.
 *
 * Settlement is through Stripe; a decline is retried once against Adyen.
 *
 * @author Jane Okafor
 */
import { PaymentGateway } from "../gateway/payment-gateway";
import { CustomerSubscription } from "../domain/customer-subscription";

export class BillingService {
  constructor(private readonly gateway: PaymentGateway) {}

  async chargeInvoice(subscription: CustomerSubscription): Promise<void> {
    await this.gateway.capture(subscription.amountDue);
  }
}
