# Local parser corpora

Corpus data is intentionally excluded from version control because real APRS
packets can contain callsigns, positions, and message text.

The default local corpus path is:

```text
test-data/real-world-1m.tnc2
```

It contains one exact TNC2/APRS-IS packet per line. A sibling
`real-world-1m.tnc2.manifest.json` records its source time range, row counts,
size, and SHA-256 checksum.
