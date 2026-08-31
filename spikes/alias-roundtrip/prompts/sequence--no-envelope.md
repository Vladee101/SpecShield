Add retry with exponential backoff to the create method, and write one unit test for it. Return the full file.

```ts
export class SERVICE_014 {
  constructor(private readonly repo: DTO_M4X2Q7) {}

  async create(input: DTO_M4X2Q7): Promise<EVENT_K9P3Q2> {
    return this.repo.insert(input);
  }
}
```
