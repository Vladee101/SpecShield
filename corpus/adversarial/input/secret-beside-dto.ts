import { CreateSubscriptionDto } from "./dto";

// A live-looking credential three lines from a DTO: the secret must be redacted
// one-way while the DTO is pseudonymized two-way. They must not share a path.
const PAYLANE_KEY = "sk_test_00000000000000000000000000000000";

export function submit(dto: CreateSubscriptionDto): void {
  void dto;
  void PAYLANE_KEY;
}
