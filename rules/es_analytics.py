"""
Copyright(C) 2015-2022, Stamus Networks
Written by Markus Kont <markus@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
"""

from rules.es_query import ESQuery


class ESGetUniqueFields(ESQuery):

    def _walk_properties(self, d: dict) -> list:
        tx = []
        for k, v in d.items():
            if "properties" in v:
                sub = self._walk_properties(v["properties"])
                sub = [k + "." + item for item in sub]
                tx.extend(sub)
            else:
                tx.append(k)
        return tx

    def get(self, event_type=None) -> dict:
        if self.es is None:
            return {}

        pattern = "logstash-*"
        if event_type is not None:
            pattern = "logstash-%s-*" % event_type
        resp = self.es.indices.get_mapping(index=pattern)
        fields = []
        for k in resp:
            fields.extend(self._walk_properties(d=resp[k].get("mappings", {}).get("properties", {})))
        return {
            "fields": sorted(list(set(fields)))
        }
