Tokens matching `^[A-Z][A-Za-z0-9_]*_[A-Z0-9]{3,8}$` are opaque anonymized identifiers. Preserve them exactly — do not rename, expand, translate, pluralize, or reformat them. If you introduce a new entity, name it `NEW_<n>` and list every such name at the end of your response.

Add retry with exponential backoff to the create method, and write one unit test for it. Return the full file.

```ts
export class AuroraService {
  constructor(private readonly repo: DTO_M4X2Q7) {}

  async create(input: DTO_M4X2Q7): Promise<EVENT_K9P3Q2> {
    return this.repo.insert(input);
  }
}
```
