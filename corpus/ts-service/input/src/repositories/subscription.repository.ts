import { CustomerSubscription } from "../domain/customer-subscription";

export interface SubscriptionRepository {
  findByCustomer(customerId: string): Promise<CustomerSubscription | null>;
  insert(subscription: CustomerSubscription): Promise<void>;
}
