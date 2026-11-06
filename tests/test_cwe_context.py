import unittest
from pathlib import Path
from Definitions.cwe import recorded_cwe_context
from Graph.Nodes.formatters import formatter

class CWEContextTests(unittest.TestCase):
    def test_normalization_and_provenance(self):
        weaknesses = [{'source': s, 'description': [{'value': v}]} for s, v in [('b',' cwe-079 '),('a','CWE-79'),('a','NVD-CWE-noinfo'),('a','NVD-CWE-Other')]]
        result = recorded_cwe_context(weaknesses)
        self.assertEqual(result, recorded_cwe_context(list(reversed(weaknesses))))
        self.assertEqual([r['id'] for r in result['cwe_associations']], ['CWE-79'])
        self.assertIn('Improper Neutralization', result['cwe_context'])
        self.assertEqual(len(result['cwe_associations'][0]['recorded_by']), 2)
        state = formatter({'cve_id':'CVE-test','nvd_description':'description','summaries':{}, **result})
        self.assertIn(result['cwe_context'], state['rag'])

    def test_missing(self):
        self.assertIn('No usable CWE', recorded_cwe_context([])['cwe_context'])
        result = recorded_cwe_context([{'description':[{'value':'CWE-999999'}]}], Path('/nonexistent/catalogue'))
        self.assertIn('Definition unavailable', result['cwe_context'])
        self.assertEqual(result['cwe_catalogue']['status'], 'unavailable')
