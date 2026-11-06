"""Recorded NVD associations enriched exclusively from a bundled MITRE catalogue."""
import json
import re
from pathlib import Path

CATALOGUE = Path(__file__).resolve().parents[2] / 'fixtures/cwe/catalogue.json'


def recorded_cwe_context(weaknesses: list, catalogue_path: Path = CATALOGUE) -> dict:
    associations: dict[str, set[tuple[str, str]]] = {}
    for weakness in weaknesses if isinstance(weaknesses, list) else []:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get('description', []):
            value = description.get('value', '') if isinstance(description, dict) else ''
            match = re.fullmatch(r'CWE-0*(\d+)', str(value).strip(), re.IGNORECASE)
            if match:
                identifier = f'CWE-{int(match[1])}'
                associations.setdefault(identifier, set()).add((str(weakness.get('source', 'unknown')), str(weakness.get('type', 'unknown'))))
    try:
        catalogue = json.loads(catalogue_path.read_text())
        definitions = catalogue['definitions']
        provenance = {k: v for k, v in catalogue.items() if k != 'definitions'}
        provenance['status'] = 'available'
    except (OSError, ValueError, KeyError):
        definitions = {}
        provenance = {'status': 'unavailable'}
    lines = ['The NVD record associates this CVE with the following weaknesses:']
    records = []
    for identifier in sorted(associations, key=lambda x: int(x[4:])):
        definition = definitions.get(identifier, {})
        records.append({'id': identifier, 'recorded_by': [{'source': s, 'type': t} for s, t in sorted(associations[identifier])], 'definition': definition})
        if definition.get('name') and definition.get('description'):
            lines.append(f"{identifier} — Name: {definition['name']} Description: {definition['description']}")
        else:
            lines.append(f'{identifier} — Definition unavailable; do not reconstruct it.')
    if not records:
        lines.append('No usable CWE assignments recorded; this does not establish absence of a weakness.')
    lines.append('Catalogue: ' + json.dumps(provenance, sort_keys=True))
    lines.append('These recorded associations provide supporting context, not independently verified ground truth or automatic custom-label predictions. Evaluate the supplied classification labels against their definitions and the available vulnerability information. Do not reconstruct missing CWE definitions.')
    return {'cwe_associations': records, 'cwe_catalogue': provenance, 'cwe_context': '\n'.join(lines)}
