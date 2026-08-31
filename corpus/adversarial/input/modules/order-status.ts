// One of three unrelated `Status` enums. Each must receive its own alias:
// collapsing them by name breaks the twin and makes restore ambiguous.
export enum Status {
  Draft = "draft",
  Placed = "placed",
  Shipped = "shipped",
}
