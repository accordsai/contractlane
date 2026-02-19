# AMOUNT_V1

Normalized amount object:

```json
{ "currency": "USD", "amount": "49.01" }
```

## Rules

- `currency` is ISO4217 uppercase (3 letters).
- `amount` is a normalized decimal string.
- No scientific notation, no `+`, no float transport semantics.
- Comparison logic uses integer minor units with the protocol exponent table.

## v1 Minor Unit Table

- `USD:2`, `EUR:2`, `GBP:2`, `JPY:0`, `KRW:0`, `INR:2`, `CHF:2`, `CAD:2`, `AUD:2`
