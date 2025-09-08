"""
Takes Enumerated Infrastructure and Version Numbers
and uses them to query NVD and return potential CVEs
that could affect endpoints.
"""

import nvdlib
"""
I'm not sure how we're going to approach this tbh.
CPEs seem to be the best way to search for CVEs, but

true?
apparently you can't search for CVEs based on CPE
anymore on NVD?
true?

So I need to workshop the best workflow.
"""