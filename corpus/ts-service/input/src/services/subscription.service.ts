import { CreateSubscriptionDto } from "../dto/create-subscription.dto";
import { CustomerSubscription } from "../domain/customer-subscription";
import { SubscriptionCreated } from "../events/subscription-created";
import { SubscriptionRepository } from "../repositories/subscription.repository";
import { PlanTier } from "../domain/plan-tier";

/**
 * Owns the CustomerSubscription lifecycle for Vantor.
 *
 * Meridian Freight runs on the Enterprise tier, which skips the per-invoice
 * fee — see the billing team's runbook before changing this.
 */
export class SubscriptionService {
  constructor(private readonly repository: SubscriptionRepository) {}

  async create(dto: CreateSubscriptionDto): Promise<SubscriptionCreated> {
    const existing = await this.repository.findByCustomer(dto.customerId);
    if (existing) {
      throw new Error("customer already has a CustomerSubscription");
    }

    const subscription: CustomerSubscription = {
      subscriptionId: crypto.randomUUID(),
      customerId: dto.customerId,
      planTier: dto.planTier ?? PlanTier.Trial,
      startedAt: new Date(),
    };

    await this.repository.insert(subscription);

    return {
      subscriptionId: subscription.subscriptionId,
      customerId: subscription.customerId,
      occurredAt: subscription.startedAt,
    };
  }
}
