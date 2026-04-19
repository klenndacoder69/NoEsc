# NoEsc Run Commands (Copy/Paste)

Run in this order.

## 1) Start ML listener (Terminal A)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rm -f final_ml_listener.log /tmp/noesc_ml.sock
python src/ml_engine/model_interface.py \
	--short-seq-policy infer \
	--emit-benign \
	--emit-auth-only \
	--short-model-enabled \
	--short-model-path models/short_v1/svm_model.pkl \
	--short-vectorizer-path models/short_v1/tfidf_vectorizer.pkl \
	--short-metadata-path models/short_v1/training_metadata.json \
	--short-model-max-seq-len 2 \
	--short-malicious-score-threshold 0.5 | tee final_ml_listener.log
```

Leave this terminal running.

## 2) Replay audit data with pacing (Terminal B)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
while IFS= read -r line; do
	printf '%s\n' "$line"
	sleep 0.002
done < sample_set/audit.log.1 | ./noesc_daemon --ml-only
```

## 3) Summarize listener output (Terminal C)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
python scripts/ml/summarize_ml_listener_log.py --log final_ml_listener.log
```

## 4) Check bridge drops (always prints a number)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rg --count --include-zero "ML Bridge Offline \(Resource temporarily unavailable\)" final_ml_listener.log
```

## 5) Short-model malicious score diagnostics

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
awk '
/^\[ML-DETECT\]/ {
	label=""; src=""; score=0;
	for(i=1;i<=NF;i++){
		if($i~/^label=/){split($i,a,"="); label=a[2]}
		if($i~/^model_source=/){split($i,a,"="); src=a[2]}
		if($i~/^score=/){split($i,a,"="); score=a[2]+0}
	}
	if(label=="MALICIOUS" && src=="short"){n++; s+=score; if(score>=0.9) h90++; if(score<0.1) l10++}
}
END{
	printf("short_malicious_count=%d avg_score=%.6f ge_0.9=%d lt_0.1=%d\n", n, (n?s/n:0), h90, l10)
}' final_ml_listener.log
```

## 6) Threshold simulation for short model (0.5)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
awk '
/^\[ML-DETECT\]/ {
	label=""; src=""; score=0;
	for(i=1;i<=NF;i++){
		if($i~/^label=/){split($i,a,"="); label=a[2]}
		if($i~/^model_source=/){split($i,a,"="); src=a[2]}
		if($i~/^score=/){split($i,a,"="); score=a[2]+0}
	}
	total++;
	if(label=="MALICIOUS") raw++;
	if(label=="MALICIOUS" && !(src=="short" && score<0.5)) t05++;
}
END{
	printf("raw_mal=%d raw_rate=%.2f%%\n", raw, 100*raw/total);
	printf("short_score>=0.5 mal=%d rate=%.2f%%\n", t05, 100*t05/total);
}' final_ml_listener.log
```

## 7) Evaluate by length bucket (1, 2, 3+)

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
awk '
/^\[ML-DETECT\]/ {
	label=""; src=""; score=0; seq=0;
	for(i=1;i<=NF;i++){
		if($i~/^label=/){split($i,a,"="); label=a[2]}
		if($i~/^model_source=/){split($i,a,"="); src=a[2]}
		if($i~/^score=/){split($i,a,"="); score=a[2]+0}
		if($i~/^seq_len=/){split($i,a,"="); seq=a[2]+0}
	}

	bucket = (seq<=1 ? "len1" : (seq==2 ? "len2" : "len3plus"));
	total[bucket]++;

	if(label=="MALICIOUS") raw_mal[bucket]++;

	# Simulated calibrated decision: only short malicious with score>=0.5 stays malicious.
	cal_mal = (label=="MALICIOUS" && !(src=="short" && score<0.5));
	if(cal_mal) cal_mal_count[bucket]++;
}
END {
	printf("bucket,total,raw_mal,raw_rate_pct,cal_mal,cal_rate_pct\n");
	for (b in total) {
		raw_rate = (total[b] ? 100.0*raw_mal[b]/total[b] : 0);
		cal_rate = (total[b] ? 100.0*cal_mal_count[b]/total[b] : 0);
		printf("%s,%d,%d,%.2f,%d,%.2f\n", b, total[b], raw_mal[b], raw_rate, cal_mal_count[b], cal_rate);
	}
}' final_ml_listener.log | sort
```

## 8) Fairness comparison automation (run this yourself)

Quick smoke check (1 run per mode):

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
python scripts/eval/run_fairness_comparison.py \
	--input-log sample_set/audit.log.1 \
	--repeats 1 \
	--ml-replay-delay-ms 0.0 \
	--rules-replay-delay-ms 0.0 \
	--short-malicious-score-threshold 0.5 \
	--out-dir out/fairness_comparison_smoke
```

Full benchmark (3 runs per mode):

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
python scripts/eval/run_fairness_comparison.py \
	--input-log sample_set/audit.log.1 \
	--repeats 3 \
	--ml-replay-delay-ms 2.0 \
	--rules-replay-delay-ms 0.0 \
	--short-malicious-score-threshold 0.5 \
	--out-dir out/fairness_comparison
```

After it finishes, print summary:

```bash
cd /home/swuffles/Documents/NoEsc
cat out/fairness_comparison/summary.txt
```

Optional: inspect per-run CSV:

```bash
cd /home/swuffles/Documents/NoEsc
cat out/fairness_comparison/per_run_metrics.csv
```

## 9) Rules-only sanity check (safe output, no missing-file error)

Test rules-only on audit.log.1:

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rm -f noesc_alerts.log /tmp/rules_audit1.out
cat sample_set/audit.log.1 | ./noesc_daemon --rules-only >/tmp/rules_audit1.out 2>&1

echo "stderr_alert_lines:"
rg --count --include-zero "\\[!\\] NoEsc ALERT" /tmp/rules_audit1.out

echo "workspace_log_total:"
if [[ -f noesc_alerts.log ]]; then
	rg --count --include-zero "ALERT \\[" noesc_alerts.log
else
	echo "0 (no workspace noesc_alerts.log created)"
fi
```

Test rules-only on a known trigger dataset:

```bash
cd /home/swuffles/Documents/NoEsc
source .venv/bin/activate
rm -f noesc_alerts.log /tmp/rules_trigger.out
cat sample_set/yay_kernel_install_like.log | ./noesc_daemon --rules-only >/tmp/rules_trigger.out 2>&1

echo "stderr_alert_lines:"
rg --count --include-zero "\\[!\\] NoEsc ALERT" /tmp/rules_trigger.out

echo "workspace_warning_sudomisuse:"
if [[ -f noesc_alerts.log ]]; then
	rg --count --include-zero "WARNING ALERT \\[SudoMisuse\\]" noesc_alerts.log
else
	echo "0 (no workspace noesc_alerts.log created)"
fi

echo "workspace_critical_sudomisuse:"
if [[ -f noesc_alerts.log ]]; then
	rg --count --include-zero "CRITICAL ALERT \\[SudoMisuse\\]" noesc_alerts.log
else
	echo "0 (no workspace noesc_alerts.log created)"
fi
```
