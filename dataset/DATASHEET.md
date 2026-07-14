# Datasheet — Level 3 Industrial Honeynet Session Dataset

## Motivation
Labelled, session-level attacker datasets for the *upper* (Purdue Level 3)
layer of ICS are scarce; most public ICS security data is packet- or
field-device-level. This dataset captures multi-step attacker and benign
**sessions** against a Level 3 honeynet (engineering workstation, SMB share,
historian, OPC UA server), each event labelled with a kill-chain stage and a
MITRE ATT&CK for ICS technique, to support session-level detection research.

## Composition
- **Sessions:** 257 (190 attack, 67 benign)
- **Events:** 1261
- **Distinct session intents:** 13
- **MITRE ATT&CK for ICS techniques covered:** 11
- **Public subset:** 134 sessions / 537 events (balanced)

## Collection process
Sessions are produced by (a) curated scenario templates with timing/ordering
variation and (b) live sensor replay of an eight-step kill chain aligned to
MITRE ATT&CK for ICS. Labels are recorded as ground truth at generation time,
not inferred after the fact.

## Sanitisation / privacy
- Absolute host paths are removed; `output_file` blobs are not released.
- Lab IP addresses are RFC1918 (non-routable) and are retained, consistent
  with the published thesis topology.
- The `john / Cisco` credential appearing in some commands is **synthetic bait**
  from the honeynet's deception design — it is not a real secret.
- No personal data, no real user accounts, and no real industrial infrastructure
  are represented.

## Recommended uses
Session-level intrusion classification, kill-chain stage prediction, early-warning
/ partial-session prediction, and MITRE-labelled ICS attack analysis.

## Limitations
The dataset is generated in a single-testbed, closed-world setting; absolute
class frequencies reflect scenario design choices, not field base rates. It is
intended for methodology research, not as a representative traffic sample.

## License / citation
Release under CC BY 4.0 (suggested). Cite the accompanying paper.
