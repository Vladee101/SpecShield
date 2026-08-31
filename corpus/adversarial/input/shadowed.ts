import { CustomerSubscription } from "./domain";

// `subscription` is bound three times at three different scopes. Renaming the
// outer binding must not touch the inner ones.
const subscription = "module-level";

export function render(subscription: CustomerSubscription): string {
  {
    const subscription = subscription_label();
    return subscription;
  }
}

function subscription_label(): string {
  return "inner";
}
