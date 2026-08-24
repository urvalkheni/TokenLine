# Proposed Schema Changes

To support the **Token-Family Correlator** component, the event schema needs to represent links between old (parent) tokens and new (rotated) tokens.

## Proposed Addition: `parent_token_hash`

* **Field Name**: `parent_token_hash`
* **Type**: `string`
* **Required**: No (Only relevant for rotation/successor events, not root issuance or use events)
* **Description**: Holds the privacy-preserving hash of the parent token that this token superseded.

### Rationale
Without linking the parent token to the child token in the payload of `token_refreshed` events, there is no deterministic way to identify which token was rotated to produce the new token. Adding `parent_token_hash` allows the correlator to link children to parents correctly, build rotation chains, and accurately check for reuse conditions.

### Schema Modification
We propose adding the following field definition to `properties` in `schema/event.schema.json`:

```json
    "parent_token_hash": {
      "type": "string",
      "description": "Privacy-preserving hash of the parent token that this token superseded"
    }
```
