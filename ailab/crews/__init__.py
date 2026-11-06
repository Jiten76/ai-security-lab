"""The crew registry. Add a crew module here and it joins the lab."""

from ailab.crews.dataops import CREW as dataops
from ailab.crews.finops import CREW as finops
from ailab.crews.helpdesk import CREW as helpdesk
from ailab.crews.support import CREW as support

REGISTRY = [helpdesk, finops, support, dataops]
