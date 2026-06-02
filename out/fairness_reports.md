# NoEsc Fairness Comparison Reports

These are the fairness evaluation summaries comparing ML-only and Rules-only detection modes across different dataset configurations.

---

### fairness_comparison

```text
================================================================
NoEsc Fairness Comparison Summary
================================================================
runs_per_mode: 3
----------------------------------------------------------------
ML-only (calibrated dual-model)
  mean alerts total             : 92.00
  mean alert rate / input events: 0.1014%
  mean len1 malicious rate      : 2.1512%
  mean len2 malicious rate      : 0.3190%
  mean len3+ malicious rate     : 4.1999%
  mean bridge drop count        : 0.00
----------------------------------------------------------------
Rules-only
  mean alerts total             : 0.00
  mean alert rate / input events: 0.0000%
  mean WARNING alerts           : 0.00
  mean CRITICAL alerts          : 0.00
----------------------------------------------------------------

```

### fairness_comparison_mixed

```text
================================================================
NoEsc Fairness Comparison Summary
================================================================
runs_per_mode: 3
----------------------------------------------------------------
ML-only (calibrated dual-model)
  mean alerts total             : 108.00
  mean alert rate / input events: 0.1190%
  mean len1 malicious rate      : 2.2971%
  mean len2 malicious rate      : 0.4367%
  mean len3+ malicious rate     : 3.3619%
  mean bridge drop count        : 0.00
----------------------------------------------------------------
Rules-only
  mean alerts total             : 7.00
  mean alert rate / input events: 0.0077%
  mean WARNING alerts           : 2.00
  mean CRITICAL alerts          : 5.00
----------------------------------------------------------------

```

### fairness_comparison_smoke

```text
================================================================
NoEsc Fairness Comparison Summary
================================================================
runs_per_mode: 1
----------------------------------------------------------------
ML-only (calibrated dual-model)
  mean alerts total             : 30.00
  mean alert rate / input events: 0.0331%
  mean len1 malicious rate      : 2.4038%
  mean len2 malicious rate      : 2.4096%
  mean len3+ malicious rate     : 1.2821%
  mean bridge drop count        : 0.00
----------------------------------------------------------------
Rules-only
  mean alerts total             : 0.00
  mean alert rate / input events: 0.0000%
  mean WARNING alerts           : 0.00
  mean CRITICAL alerts          : 0.00
----------------------------------------------------------------

```

### fairness_with_whitelist

```text
================================================================
NoEsc Fairness Comparison Summary
================================================================
runs_per_mode: 3
----------------------------------------------------------------
ML-only (calibrated dual-model)
  mean alerts total             : 89.33
  mean alert rate / input events: 0.0985%
  mean len1 malicious rate      : 2.6453%
  mean len2 malicious rate      : 0.2112%
  mean len3+ malicious rate     : 2.0337%
  mean bridge drop count        : 0.00
----------------------------------------------------------------
Rules-only
  mean alerts total             : 7.00
  mean alert rate / input events: 0.0077%
  mean WARNING alerts           : 2.00
  mean CRITICAL alerts          : 5.00
----------------------------------------------------------------

```

### fairness_with_whitelist_v2

```text
================================================================
NoEsc Fairness Comparison Summary
================================================================
runs_per_mode: 3
----------------------------------------------------------------
ML-only (calibrated dual-model)
  mean alerts total             : 28.33
  mean alert rate / input events: 0.0312%
  mean len1 malicious rate      : 0.8553%
  mean len2 malicious rate      : 0.3284%
  mean len3+ malicious rate     : 0.7675%
  mean bridge drop count        : 0.00
----------------------------------------------------------------
Rules-only
  mean alerts total             : 7.00
  mean alert rate / input events: 0.0077%
  mean WARNING alerts           : 2.00
  mean CRITICAL alerts          : 5.00
----------------------------------------------------------------

```

