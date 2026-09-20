# Local parser datasets

Large or changing dataset files are excluded from version control to avoid
permanently enlarging the repository and its history. Callsigns and positions
are expected in amateur-radio transmissions and do not require anonymization
merely because they appear in a capture. Check the source terms and review
free-form messages before redistributing a dataset.

The default local dataset path is:

```text
test-data/real-world-1m.tnc2
```

It contains one exact TNC2/APRS-IS packet per line. A sibling
`real-world-1m.tnc2.manifest.json` records its source time range, row counts,
size, and SHA-256 checksum.

See the root README's `Capturing a dataset` section for the FRAP APRS-IS
recorder example.
