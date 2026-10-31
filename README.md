# PULSAR OCULUS - V2.1 by Cheick 🇲🇱
![PULSAR](https://github.com/Cheickoumarly330-cmyk/Pulsar-oculus-/actions/workflows/pulsar.yml/badge.svg)

> Auto Scanner for Sherlock / Cantina Bounties - From Bamako

### How it works
- Skips `node_modules`, `lib`, `artifacts`
- Detects: REENTRANCY, TX_ORIGIN, ACCESS_CONTROL, UNCHECKED_MINT
- Protects `withdraw` with `onlyOwner` check -> LOW severity
- Exports: `rapport.json` + `rapport_SHERLOCK.md` + `rapport.txt`

### Run locally
python pulsar_bounty.py ./src
