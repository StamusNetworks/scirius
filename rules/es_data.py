'''
Copyright(C) 2016, Stamus Networks
Written by Laurent Defert <lds@stamus-networks.com>

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
'''


import logging
import json
import os
import sys
import tarfile
import tempfile
from shutil import rmtree
from time import strftime, sleep

import urllib.request

from django.conf import settings
from elasticsearch import ConnectionError

from rules.es_graphs import get_es_major_version, ESError
from rules.es_query import ESQuery

# Avoid logging every request
ES_LOGGER = logging.getLogger('elasticsearch')
ES_LOGGER.setLevel(logging.INFO)


# Mapping
def get_kibana_mappings():
    if get_es_major_version() < 6:
        return {
            "dashboard": {
                "properties": {
                    "title": {"type": "string"},
                    "hits": {"type": "integer"},
                    "description": {"type": "string"},
                    "panelsJSON": {"type": "string"},
                    "optionsJSON": {"type": "string"},
                    "uiStateJSON": {"type": "string"},
                    "version": {"type": "integer"},
                    "timeRestore": {"type": "boolean"},
                    "timeTo": {"type": "string"},
                    "timeFrom": {"type": "string"},
                }
            },
            "search": {
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "hits": {"type": "integer"},
                    "columns": {"type": "string"},
                    "sort": {"type": "string"},
                    "version": {"type": "integer"}
                }
            },
            "visualization": {
                "properties": {
                    "title": {"type": "string"},
                    "uiStateJSON": {"type": "string"},
                    "description": {"type": "string"},
                    "savedSearchId": {"type": "string"},
                    "version": {"type": "integer"}
                }
            }
        }
    elif get_es_major_version() < 7:
        return {
            "doc": {
                "properties": {
                    "config": {
                        "properties": {
                            "buildNum": {
                                "type": "keyword"
                            },
                            "defaultIndex": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "telemetry:optIn": {
                                "type": "boolean"
                            }
                        }
                    },
                    "dashboard": {
                        "properties": {
                            "description": {
                                "type": "text"
                            },
                            "hits": {
                                "type": "integer"
                            },
                            "kibanaSavedObjectMeta": {
                                "properties": {
                                    "searchSourceJSON": {
                                        "type": "text"
                                    }
                                }
                            },
                            "optionsJSON": {
                                "type": "text"
                            },
                            "panelsJSON": {
                                "type": "text"
                            },
                            "refreshInterval": {
                                "properties": {
                                    "display": {
                                        "type": "keyword"
                                    },
                                    "pause": {
                                        "type": "boolean"
                                    },
                                    "section": {
                                        "type": "integer"
                                    },
                                    "value": {
                                        "type": "integer"
                                    }
                                }
                            },
                            "timeFrom": {
                                "type": "keyword"
                            },
                            "timeRestore": {
                                "type": "boolean"
                            },
                            "timeTo": {
                                "type": "keyword"
                            },
                            "title": {
                                "type": "text"
                            },
                            "uiStateJSON": {
                                "type": "text"
                            },
                            "version": {
                                "type": "integer"
                            }
                        }
                    },
                    "graph-workspace": {
                        "properties": {
                            "description": {
                                "type": "text"
                            },
                            "kibanaSavedObjectMeta": {
                                "properties": {
                                    "searchSourceJSON": {
                                        "type": "text"
                                    }
                                }
                            },
                            "numLinks": {
                                "type": "integer"
                            },
                            "numVertices": {
                                "type": "integer"
                            },
                            "title": {
                                "type": "text"
                            },
                            "version": {
                                "type": "integer"
                            },
                            "wsState": {
                                "type": "text"
                            }
                        }
                    },
                    "index-pattern": {
                        "properties": {
                            "fieldFormatMap": {
                                "type": "text"
                            },
                            "fields": {
                                "type": "text"
                            },
                            "intervalName": {
                                "type": "keyword"
                            },
                            "notExpandable": {
                                "type": "boolean"
                            },
                            "sourceFilters": {
                                "type": "text"
                            },
                            "timeFieldName": {
                                "type": "keyword"
                            },
                            "title": {
                                "type": "text"
                            }
                        }
                    },
                    "search": {
                        "properties": {
                            "columns": {
                                "type": "keyword"
                            },
                            "description": {
                                "type": "text"
                            },
                            "hits": {
                                "type": "integer"
                            },
                            "kibanaSavedObjectMeta": {
                                "properties": {
                                    "searchSourceJSON": {
                                        "type": "text"
                                    }
                                }
                            },
                            "sort": {
                                "type": "keyword"
                            },
                            "title": {
                                "type": "text"
                            },
                            "version": {
                                "type": "integer"
                            }
                        }
                    },
                    "server": {
                        "properties": {
                            "uuid": {
                                "type": "keyword"
                            }
                        }
                    },
                    "timelion-sheet": {
                        "properties": {
                            "description": {
                                "type": "text"
                            },
                            "hits": {
                                "type": "integer"
                            },
                            "kibanaSavedObjectMeta": {
                                "properties": {
                                    "searchSourceJSON": {
                                        "type": "text"
                                    }
                                }
                            },
                            "timelion_chart_height": {
                                "type": "integer"
                            },
                            "timelion_columns": {
                                "type": "integer"
                            },
                            "timelion_interval": {
                                "type": "keyword"
                            },
                            "timelion_other_interval": {
                                "type": "keyword"
                            },
                            "timelion_rows": {
                                "type": "integer"
                            },
                            "timelion_sheet": {
                                "type": "text"
                            },
                            "title": {
                                "type": "text"
                            },
                            "version": {
                                "type": "integer"
                            }
                        }
                    },
                    "type": {
                        "type": "keyword"
                    },
                    "updated_at": {
                        "type": "date"
                    },
                    "url": {
                        "properties": {
                            "accessCount": {
                                "type": "long"
                            },
                            "accessDate": {
                                "type": "date"
                            },
                            "createDate": {
                                "type": "date"
                            },
                            "url": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 2048
                                    }
                                }
                            }
                        }
                    },
                    "visualization": {
                        "properties": {
                            "description": {
                                "type": "text"
                            },
                            "kibanaSavedObjectMeta": {
                                "properties": {
                                    "searchSourceJSON": {
                                        "type": "text"
                                    }
                                }
                            },
                            "savedSearchId": {
                                "type": "keyword"
                            },
                            "title": {
                                "type": "text"
                            },
                            "uiStateJSON": {
                                "type": "text"
                            },
                            "version": {
                                "type": "integer"
                            },
                            "visState": {
                                "type": "text"
                            }
                        }
                    }
                }
            }
        }
    else:
        return {
            "properties": {
                "action": {
                    "properties": {
                        "actionTypeId": {
                            "type": "keyword"
                        },
                        "config": {
                            "type": "object",
                            "enabled": False
                        },
                        "name": {
                            "type": "text"
                        },
                        "secrets": {
                            "type": "binary"
                        }
                    }
                },
                "action_task_params": {
                    "properties": {
                        "actionId": {
                            "type": "keyword"
                        },
                        "apiKey": {
                            "type": "binary"
                        },
                        "params": {
                            "type": "object",
                            "enabled": False
                        }
                    }
                },
                "alert": {
                    "properties": {
                        "actions": {
                            "type": "nested",
                            "properties": {
                                "actionRef": {
                                    "type": "keyword"
                                },
                                "actionTypeId": {
                                    "type": "keyword"
                                },
                                "group": {
                                    "type": "keyword"
                                },
                                "params": {
                                    "type": "object",
                                    "enabled": False
                                }
                            }
                        },
                        "alertTypeId": {
                            "type": "keyword"
                        },
                        "apiKey": {
                            "type": "binary"
                        },
                        "apiKeyOwner": {
                            "type": "keyword"
                        },
                        "consumer": {
                            "type": "keyword"
                        },
                        "createdAt": {
                            "type": "date"
                        },
                        "createdBy": {
                            "type": "keyword"
                        },
                        "enabled": {
                            "type": "boolean"
                        },
                        "muteAll": {
                            "type": "boolean"
                        },
                        "mutedInstanceIds": {
                            "type": "keyword"
                        },
                        "name": {
                            "type": "text"
                        },
                        "params": {
                            "type": "object",
                            "enabled": False
                        },
                        "schedule": {
                            "properties": {
                                "interval": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "scheduledTaskId": {
                            "type": "keyword"
                        },
                        "tags": {
                            "type": "keyword"
                        },
                        "throttle": {
                            "type": "keyword"
                        },
                        "updatedBy": {
                            "type": "keyword"
                        }
                    }
                },
                "apm-indices": {
                    "properties": {
                        "apm_oss": {
                            "properties": {
                                "errorIndices": {
                                    "type": "keyword"
                                },
                                "metricsIndices": {
                                    "type": "keyword"
                                },
                                "onboardingIndices": {
                                    "type": "keyword"
                                },
                                "sourcemapIndices": {
                                    "type": "keyword"
                                },
                                "spanIndices": {
                                    "type": "keyword"
                                },
                                "transactionIndices": {
                                    "type": "keyword"
                                }
                            }
                        }
                    }
                },
                "apm-services-telemetry": {
                    "properties": {
                        "has_any_services": {
                            "type": "boolean"
                        },
                        "services_per_agent": {
                            "properties": {
                                "dotnet": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "go": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "java": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "js-base": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "nodejs": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "python": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "ruby": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "rum-js": {
                                    "type": "long",
                                    "null_value": 0
                                }
                            }
                        }
                    }
                },
                "canvas-element": {
                    "dynamic": "false",
                    "properties": {
                        "@created": {
                            "type": "date"
                        },
                        "@timestamp": {
                            "type": "date"
                        },
                        "content": {
                            "type": "text"
                        },
                        "help": {
                            "type": "text"
                        },
                        "image": {
                            "type": "text"
                        },
                        "name": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword"
                                }
                            }
                        }
                    }
                },
                "canvas-workpad": {
                    "dynamic": "false",
                    "properties": {
                        "@created": {
                            "type": "date"
                        },
                        "@timestamp": {
                            "type": "date"
                        },
                        "name": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword"
                                }
                            }
                        }
                    }
                },
                "config": {
                    "dynamic": "true",
                    "properties": {
                        "buildNum": {
                            "type": "keyword"
                        }
                    }
                },
                "dashboard": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "hits": {
                            "type": "integer"
                        },
                        "kibanaSavedObjectMeta": {
                            "properties": {
                                "searchSourceJSON": {
                                    "type": "text"
                                }
                            }
                        },
                        "optionsJSON": {
                            "type": "text"
                        },
                        "panelsJSON": {
                            "type": "text"
                        },
                        "refreshInterval": {
                            "properties": {
                                "display": {
                                    "type": "keyword"
                                },
                                "pause": {
                                    "type": "boolean"
                                },
                                "section": {
                                    "type": "integer"
                                },
                                "value": {
                                    "type": "integer"
                                }
                            }
                        },
                        "timeFrom": {
                            "type": "keyword"
                        },
                        "timeRestore": {
                            "type": "boolean"
                        },
                        "timeTo": {
                            "type": "keyword"
                        },
                        "title": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        }
                    }
                },
                "file-upload-telemetry": {
                    "properties": {
                        "filesUploadedTotalCount": {
                            "type": "long"
                        }
                    }
                },
                "graph-workspace": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "kibanaSavedObjectMeta": {
                            "properties": {
                                "searchSourceJSON": {
                                    "type": "text"
                                }
                            }
                        },
                        "numLinks": {
                            "type": "integer"
                        },
                        "numVertices": {
                            "type": "integer"
                        },
                        "title": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        },
                        "wsState": {
                            "type": "text"
                        }
                    }
                },
                "index-pattern": {
                    "properties": {
                        "fieldFormatMap": {
                            "type": "text"
                        },
                        "fields": {
                            "type": "text"
                        },
                        "intervalName": {
                            "type": "keyword"
                        },
                        "notExpandable": {
                            "type": "boolean"
                        },
                        "sourceFilters": {
                            "type": "text"
                        },
                        "timeFieldName": {
                            "type": "keyword"
                        },
                        "title": {
                            "type": "text"
                        },
                        "type": {
                            "type": "keyword"
                        },
                        "typeMeta": {
                            "type": "keyword"
                        }
                    }
                },
                "infrastructure-ui-source": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "fields": {
                            "properties": {
                                "container": {
                                    "type": "keyword"
                                },
                                "host": {
                                    "type": "keyword"
                                },
                                "pod": {
                                    "type": "keyword"
                                },
                                "tiebreaker": {
                                    "type": "keyword"
                                },
                                "timestamp": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "logAlias": {
                            "type": "keyword"
                        },
                        "logColumns": {
                            "type": "nested",
                            "properties": {
                                "fieldColumn": {
                                    "properties": {
                                        "field": {
                                            "type": "keyword"
                                        },
                                        "id": {
                                            "type": "keyword"
                                        }
                                    }
                                },
                                "messageColumn": {
                                    "properties": {
                                        "id": {
                                            "type": "keyword"
                                        }
                                    }
                                },
                                "timestampColumn": {
                                    "properties": {
                                        "id": {
                                            "type": "keyword"
                                        }
                                    }
                                }
                            }
                        },
                        "metricAlias": {
                            "type": "keyword"
                        },
                        "name": {
                            "type": "text"
                        }
                    }
                },
                "inventory-view": {
                    "properties": {
                        "autoBounds": {
                            "type": "boolean"
                        },
                        "autoReload": {
                            "type": "boolean"
                        },
                        "boundsOverride": {
                            "properties": {
                                "max": {
                                    "type": "integer"
                                },
                                "min": {
                                    "type": "integer"
                                }
                            }
                        },
                        "customOptions": {
                            "type": "nested",
                            "properties": {
                                "field": {
                                    "type": "keyword"
                                },
                                "text": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "filterQuery": {
                            "properties": {
                                "expression": {
                                    "type": "keyword"
                                },
                                "kind": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "groupBy": {
                            "type": "nested",
                            "properties": {
                                "field": {
                                    "type": "keyword"
                                },
                                "label": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "metric": {
                            "properties": {
                                "type": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "name": {
                            "type": "keyword"
                        },
                        "nodeType": {
                            "type": "keyword"
                        },
                        "time": {
                            "type": "integer"
                        },
                        "view": {
                            "type": "keyword"
                        }
                    }
                },
                "kql-telemetry": {
                    "properties": {
                        "optInCount": {
                            "type": "long"
                        },
                        "optOutCount": {
                            "type": "long"
                        }
                    }
                },
                "lens": {
                    "properties": {
                        "expression": {
                            "type": "keyword",
                            "index": False
                        },
                        "state": {
                            "type": "flattened"
                        },
                        "title": {
                            "type": "text"
                        },
                        "visualizationType": {
                            "type": "keyword"
                        }
                    }
                },
                "lens-ui-telemetry": {
                    "properties": {
                        "count": {
                            "type": "integer"
                        },
                        "date": {
                            "type": "date"
                        },
                        "name": {
                            "type": "keyword"
                        },
                        "type": {
                            "type": "keyword"
                        }
                    }
                },
                "map": {
                    "properties": {
                        "bounds": {
                            "type": "geo_shape"
                        },
                        "description": {
                            "type": "text"
                        },
                        "layerListJSON": {
                            "type": "text"
                        },
                        "mapStateJSON": {
                            "type": "text"
                        },
                        "title": {
                            "type": "text"
                        },
                        "uiStateJSON": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        }
                    }
                },
                "maps-telemetry": {
                    "properties": {
                        "attributesPerMap": {
                            "properties": {
                                "dataSourcesCount": {
                                    "properties": {
                                        "avg": {
                                            "type": "long"
                                        },
                                        "max": {
                                            "type": "long"
                                        },
                                        "min": {
                                            "type": "long"
                                        }
                                    }
                                },
                                "emsVectorLayersCount": {
                                    "type": "object",
                                    "dynamic": "true"
                                },
                                "layerTypesCount": {
                                    "type": "object",
                                    "dynamic": "true"
                                },
                                "layersCount": {
                                    "properties": {
                                        "avg": {
                                            "type": "long"
                                        },
                                        "max": {
                                            "type": "long"
                                        },
                                        "min": {
                                            "type": "long"
                                        }
                                    }
                                }
                            }
                        },
                        "indexPatternsWithGeoFieldCount": {
                            "type": "long"
                        },
                        "mapsTotalCount": {
                            "type": "long"
                        },
                        "settings": {
                            "properties": {
                                "showMapVisualizationTypes": {
                                    "type": "boolean"
                                }
                            }
                        },
                        "timeCaptured": {
                            "type": "date"
                        }
                    }
                },
                "metrics-explorer-view": {
                    "properties": {
                        "chartOptions": {
                            "properties": {
                                "stack": {
                                    "type": "boolean"
                                },
                                "type": {
                                    "type": "keyword"
                                },
                                "yAxisMode": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "currentTimerange": {
                            "properties": {
                                "from": {
                                    "type": "keyword"
                                },
                                "interval": {
                                    "type": "keyword"
                                },
                                "to": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "name": {
                            "type": "keyword"
                        },
                        "options": {
                            "properties": {
                                "aggregation": {
                                    "type": "keyword"
                                },
                                "filterQuery": {
                                    "type": "keyword"
                                },
                                "groupBy": {
                                    "type": "keyword"
                                },
                                "limit": {
                                    "type": "integer"
                                },
                                "metrics": {
                                    "type": "nested",
                                    "properties": {
                                        "aggregation": {
                                            "type": "keyword"
                                        },
                                        "color": {
                                            "type": "keyword"
                                        },
                                        "field": {
                                            "type": "keyword"
                                        },
                                        "label": {
                                            "type": "keyword"
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "migrationVersion": {
                    "dynamic": "true",
                    "properties": {
                        "space": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 256
                                }
                            }
                        }
                    }
                },
                "ml-telemetry": {
                    "properties": {
                        "file_data_visualizer": {
                            "properties": {
                                "index_creation_count": {
                                    "type": "long"
                                }
                            }
                        }
                    }
                },
                "namespace": {
                    "type": "keyword"
                },
                "query": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "filters": {
                            "type": "object",
                            "enabled": False
                        },
                        "query": {
                            "properties": {
                                "language": {
                                    "type": "keyword"
                                },
                                "query": {
                                    "type": "keyword",
                                    "index": False
                                }
                            }
                        },
                        "timefilter": {
                            "type": "object",
                            "enabled": False
                        },
                        "title": {
                            "type": "text"
                        }
                    }
                },
                "references": {
                    "type": "nested",
                    "properties": {
                        "id": {
                            "type": "keyword"
                        },
                        "name": {
                            "type": "keyword"
                        },
                        "type": {
                            "type": "keyword"
                        }
                    }
                },
                "sample-data-telemetry": {
                    "properties": {
                        "installCount": {
                            "type": "long"
                        },
                        "unInstallCount": {
                            "type": "long"
                        }
                    }
                },
                "search": {
                    "properties": {
                        "columns": {
                            "type": "keyword"
                        },
                        "description": {
                            "type": "text"
                        },
                        "hits": {
                            "type": "integer"
                        },
                        "kibanaSavedObjectMeta": {
                            "properties": {
                                "searchSourceJSON": {
                                    "type": "text"
                                }
                            }
                        },
                        "sort": {
                            "type": "keyword"
                        },
                        "title": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        }
                    }
                },
                "server": {
                    "properties": {
                        "uuid": {
                            "type": "keyword"
                        }
                    }
                },
                "siem-detection-engine-rule-status": {
                    "properties": {
                        "alertId": {
                            "type": "keyword"
                        },
                        "lastFailureAt": {
                            "type": "date"
                        },
                        "lastFailureMessage": {
                            "type": "text"
                        },
                        "lastSuccessAt": {
                            "type": "date"
                        },
                        "lastSuccessMessage": {
                            "type": "text"
                        },
                        "status": {
                            "type": "keyword"
                        },
                        "statusDate": {
                            "type": "date"
                        }
                    }
                },
                "siem-ui-timeline": {
                    "properties": {
                        "columns": {
                            "properties": {
                                "aggregatable": {
                                    "type": "boolean"
                                },
                                "category": {
                                    "type": "keyword"
                                },
                                "columnHeaderType": {
                                    "type": "keyword"
                                },
                                "description": {
                                    "type": "text"
                                },
                                "example": {
                                    "type": "text"
                                },
                                "id": {
                                    "type": "keyword"
                                },
                                "indexes": {
                                    "type": "keyword"
                                },
                                "name": {
                                    "type": "text"
                                },
                                "placeholder": {
                                    "type": "text"
                                },
                                "searchable": {
                                    "type": "boolean"
                                },
                                "type": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "created": {
                            "type": "date"
                        },
                        "createdBy": {
                            "type": "text"
                        },
                        "dataProviders": {
                            "properties": {
                                "and": {
                                    "properties": {
                                        "enabled": {
                                            "type": "boolean"
                                        },
                                        "excluded": {
                                            "type": "boolean"
                                        },
                                        "id": {
                                            "type": "keyword"
                                        },
                                        "kqlQuery": {
                                            "type": "text"
                                        },
                                        "name": {
                                            "type": "text"
                                        },
                                        "queryMatch": {
                                            "properties": {
                                                "displayField": {
                                                    "type": "text"
                                                },
                                                "displayValue": {
                                                    "type": "text"
                                                },
                                                "field": {
                                                    "type": "text"
                                                },
                                                "operator": {
                                                    "type": "text"
                                                },
                                                "value": {
                                                    "type": "text"
                                                }
                                            }
                                        }
                                    }
                                },
                                "enabled": {
                                    "type": "boolean"
                                },
                                "excluded": {
                                    "type": "boolean"
                                },
                                "id": {
                                    "type": "keyword"
                                },
                                "kqlQuery": {
                                    "type": "text"
                                },
                                "name": {
                                    "type": "text"
                                },
                                "queryMatch": {
                                    "properties": {
                                        "displayField": {
                                            "type": "text"
                                        },
                                        "displayValue": {
                                            "type": "text"
                                        },
                                        "field": {
                                            "type": "text"
                                        },
                                        "operator": {
                                            "type": "text"
                                        },
                                        "value": {
                                            "type": "text"
                                        }
                                    }
                                }
                            }
                        },
                        "dateRange": {
                            "properties": {
                                "end": {
                                    "type": "date"
                                },
                                "start": {
                                    "type": "date"
                                }
                            }
                        },
                        "description": {
                            "type": "text"
                        },
                        "eventType": {
                            "type": "keyword"
                        },
                        "favorite": {
                            "properties": {
                                "favoriteDate": {
                                    "type": "date"
                                },
                                "fullName": {
                                    "type": "text"
                                },
                                "keySearch": {
                                    "type": "text"
                                },
                                "userName": {
                                    "type": "text"
                                }
                            }
                        },
                        "filters": {
                            "properties": {
                                "exists": {
                                    "type": "text"
                                },
                                "match_all": {
                                    "type": "text"
                                },
                                "meta": {
                                    "properties": {
                                        "alias": {
                                            "type": "text"
                                        },
                                        "controlledBy": {
                                            "type": "text"
                                        },
                                        "disabled": {
                                            "type": "boolean"
                                        },
                                        "field": {
                                            "type": "text"
                                        },
                                        "formattedValue": {
                                            "type": "text"
                                        },
                                        "index": {
                                            "type": "keyword"
                                        },
                                        "key": {
                                            "type": "keyword"
                                        },
                                        "negate": {
                                            "type": "boolean"
                                        },
                                        "params": {
                                            "type": "text"
                                        },
                                        "type": {
                                            "type": "keyword"
                                        },
                                        "value": {
                                            "type": "text"
                                        }
                                    }
                                },
                                "missing": {
                                    "type": "text"
                                },
                                "query": {
                                    "type": "text"
                                },
                                "range": {
                                    "type": "text"
                                },
                                "script": {
                                    "type": "text"
                                }
                            }
                        },
                        "kqlMode": {
                            "type": "keyword"
                        },
                        "kqlQuery": {
                            "properties": {
                                "filterQuery": {
                                    "properties": {
                                        "kuery": {
                                            "properties": {
                                                "expression": {
                                                    "type": "text"
                                                },
                                                "kind": {
                                                    "type": "keyword"
                                                }
                                            }
                                        },
                                        "serializedQuery": {
                                            "type": "text"
                                        }
                                    }
                                }
                            }
                        },
                        "savedQueryId": {
                            "type": "keyword"
                        },
                        "sort": {
                            "properties": {
                                "columnId": {
                                    "type": "keyword"
                                },
                                "sortDirection": {
                                    "type": "keyword"
                                }
                            }
                        },
                        "title": {
                            "type": "text"
                        },
                        "updated": {
                            "type": "date"
                        },
                        "updatedBy": {
                            "type": "text"
                        }
                    }
                },
                "siem-ui-timeline-note": {
                    "properties": {
                        "created": {
                            "type": "date"
                        },
                        "createdBy": {
                            "type": "text"
                        },
                        "eventId": {
                            "type": "keyword"
                        },
                        "note": {
                            "type": "text"
                        },
                        "timelineId": {
                            "type": "keyword"
                        },
                        "updated": {
                            "type": "date"
                        },
                        "updatedBy": {
                            "type": "text"
                        }
                    }
                },
                "siem-ui-timeline-pinned-event": {
                    "properties": {
                        "created": {
                            "type": "date"
                        },
                        "createdBy": {
                            "type": "text"
                        },
                        "eventId": {
                            "type": "keyword"
                        },
                        "timelineId": {
                            "type": "keyword"
                        },
                        "updated": {
                            "type": "date"
                        },
                        "updatedBy": {
                            "type": "text"
                        }
                    }
                },
                "space": {
                    "properties": {
                        "_reserved": {
                            "type": "boolean"
                        },
                        "color": {
                            "type": "keyword"
                        },
                        "description": {
                            "type": "text"
                        },
                        "disabledFeatures": {
                            "type": "keyword"
                        },
                        "imageUrl": {
                            "type": "text",
                            "index": False
                        },
                        "initials": {
                            "type": "keyword"
                        },
                        "name": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 2048
                                }
                            }
                        }
                    }
                },
                "telemetry": {
                    "properties": {
                        "enabled": {
                            "type": "boolean"
                        },
                        "lastReported": {
                            "type": "date"
                        },
                        "lastVersionChecked": {
                            "type": "keyword",
                            "ignore_above": 256
                        },
                        "sendUsageFrom": {
                            "type": "keyword",
                            "ignore_above": 256
                        },
                        "userHasSeenNotice": {
                            "type": "boolean"
                        }
                    }
                },
                "timelion-sheet": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "hits": {
                            "type": "integer"
                        },
                        "kibanaSavedObjectMeta": {
                            "properties": {
                                "searchSourceJSON": {
                                    "type": "text"
                                }
                            }
                        },
                        "timelion_chart_height": {
                            "type": "integer"
                        },
                        "timelion_columns": {
                            "type": "integer"
                        },
                        "timelion_interval": {
                            "type": "keyword"
                        },
                        "timelion_other_interval": {
                            "type": "keyword"
                        },
                        "timelion_rows": {
                            "type": "integer"
                        },
                        "timelion_sheet": {
                            "type": "text"
                        },
                        "title": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        }
                    }
                },
                "tsvb-validation-telemetry": {
                    "properties": {
                        "failedRequests": {
                            "type": "long"
                        }
                    }
                },
                "type": {
                    "type": "keyword"
                },
                "ui-metric": {
                    "properties": {
                        "count": {
                            "type": "integer"
                        }
                    }
                },
                "updated_at": {
                    "type": "date"
                },
                "upgrade-assistant-reindex-operation": {
                    "dynamic": "true",
                    "properties": {
                        "indexName": {
                            "type": "keyword"
                        },
                        "status": {
                            "type": "integer"
                        }
                    }
                },
                "upgrade-assistant-telemetry": {
                    "properties": {
                        "features": {
                            "properties": {
                                "deprecation_logging": {
                                    "properties": {
                                        "enabled": {
                                            "type": "boolean",
                                            "null_value": True
                                        }
                                    }
                                }
                            }
                        },
                        "ui_open": {
                            "properties": {
                                "cluster": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "indices": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "overview": {
                                    "type": "long",
                                    "null_value": 0
                                }
                            }
                        },
                        "ui_reindex": {
                            "properties": {
                                "close": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "open": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "start": {
                                    "type": "long",
                                    "null_value": 0
                                },
                                "stop": {
                                    "type": "long",
                                    "null_value": 0
                                }
                            }
                        }
                    }
                },
                "url": {
                    "properties": {
                        "accessCount": {
                            "type": "long"
                        },
                        "accessDate": {
                            "type": "date"
                        },
                        "createDate": {
                            "type": "date"
                        },
                        "url": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 2048
                                }
                            }
                        }
                    }
                },
                "visualization": {
                    "properties": {
                        "description": {
                            "type": "text"
                        },
                        "kibanaSavedObjectMeta": {
                            "properties": {
                                "searchSourceJSON": {
                                    "type": "text"
                                }
                            }
                        },
                        "savedSearchRefName": {
                            "type": "keyword"
                        },
                        "title": {
                            "type": "text"
                        },
                        "uiStateJSON": {
                            "type": "text"
                        },
                        "version": {
                            "type": "integer"
                        },
                        "visState": {
                            "type": "text"
                        }
                    }
                }
            }
        }


KIBANA6_NAMESPACE = {
    "id": "default",
    "name": "Default",
    "description": "This is your default space!",
    "color": "#00bfb3",
}


class ESData(ESQuery):
    def __init__(self):
        super().__init__(None)
        self.doc_type = None

        if get_es_major_version() == 6:
            self.doc_type = 'doc'
        elif get_es_major_version() == 7:
            self.doc_type = '_doc'

    @staticmethod
    def _kibana_request(url, data):
        headers = {
            'content-type': 'application/json',
            'kbn-xsrf': True
        }
        data = json.dumps(data)
        kibana_url = settings.KIBANA_URL + url
        req = urllib.request.Request(kibana_url, data.encode('utf8'), headers=headers)
        urllib.request.urlopen(req)
        return req

    def _kibana_remove(self, _type, body):
        i = 0
        ids = []

        if get_es_major_version() >= 6:
            body['query']['query_string']['query'] += ' type:%s' % _type
            _type = self.doc_type

        while True:
            res = self.es.search(index='.kibana', from_=i, doc_type=_type, body=body, request_cache=False)
            if len(res['hits']['hits']) == 0:
                break
            i += 10

            _ids = [hit['_id'] for hit in res['hits']['hits']]
            ids += _ids

        for _id in ids:
            self.es.delete(index='.kibana', doc_type=_type, id=_id, refresh=True, ignore=[404])

    def _kibana_export_obj(self, dest, _type, body):
        i = 0

        dest = os.path.join(dest, _type)
        os.makedirs(dest)

        while True:
            if get_es_major_version() < 6:
                res = self.es.search(index='.kibana', from_=i, doc_type=_type, body=body)
            else:
                res = self.es.search(index='.kibana', from_=i, body=body)

            if len(res['hits']['hits']) == 0:
                break
            i += 10

            for hit in res['hits']['hits']:

                _id = hit['_id']
                filename = os.path.join(dest, _id)
                filename += '.json'

                if get_es_major_version() < 6:
                    res = self.es.get(index='.kibana', doc_type=_type, id=_id)
                else:
                    res = self.es.get(index='.kibana', doc_type=self.doc_type, id=_id)

                with open(filename, 'w') as file_:
                    file_.write(json.dumps(res['_source'], separators=(',', ':')))

    def kibana_export(self, full=False):
        dest = tempfile.mkdtemp()
        _types = ('search', 'visualization', 'dashboard')

        if full:
            _types = _types + ('index-pattern',)

        for _type in _types:
            if get_es_major_version() < 6:
                if full:
                    body = {'query': {'match_all': {}}}
                else:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'NOT title: SN *'
                            }
                        }
                    }
            else:
                if full:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'type: %s' % _type
                            }
                        }
                    }
                else:
                    body = {
                        'query': {
                            'query_string': {
                                'query': 'type: %s AND NOT %s.title: SN' % (_type, _type)
                            }
                        }
                    }
            self._kibana_export_obj(dest, _type, body)

        file_ = tempfile.NamedTemporaryFile(delete=False)
        tar_name = 'scirius-dashboards-%s' % strftime('%Y%m%d%H%M')
        tar = tarfile.open(mode='w:bz2', fileobj=file_)
        tar.add(dest, tar_name)
        tar.close()
        rmtree(dest)
        file_.close()
        tar_name += '.tar.bz2'
        return tar_name, file_.name

    def _create_kibana_mappings(self):
        if not self.es.indices.exists('.kibana'):
            self.es.indices.create(index='.kibana', body={"mappings": get_kibana_mappings()})
            self.es.indices.refresh(index='.kibana')
        elif "visualization" not in str(self.es.indices.get_mapping(index='.kibana')):
            self.es.indices.delete(index='.kibana')
            self.es.indices.create(index='.kibana', body={"mappings": get_kibana_mappings()})
            self.es.indices.refresh(index='.kibana')

    def _kibana_inject(self, _type, _file):
        with open(_file) as file_:
            content = file_.read()
        name = _file.rsplit('/', 1)[1]
        name = name.rsplit('.', 1)[0]
        if get_es_major_version() < 6:
            doc_type = _type
        else:
            doc_type = self.doc_type

        # Delete the document first, to prevent an error when it's already there
        self.es.delete(index='.kibana', doc_type=doc_type, id=name, refresh=True, ignore=[404])

        try:
            self.es.create(index='.kibana', doc_type=doc_type, id=name, body=content, refresh=True)
        except Exception:
            print('While processing %s:\n' % _file)
            raise

    def _kibana_set_default_index(self, idx):
        if get_es_major_version() < 6:
            res = self.es.search(index='.kibana', doc_type='config', body={'query': {'match_all': {}}}, request_cache=False)
        else:
            body = {'query': {'query_string': {'query': 'type: config'}}}
            res = self.es.search(index='.kibana', doc_type=self.doc_type, body=body, request_cache=False)

        for hit in res['hits']['hits']:
            content = hit['_source']
            content['defaultIndex'] = idx

            if get_es_major_version() < 6:
                self.es.update(index='.kibana', doc_type='config', id=hit['_id'], body={'doc': content}, refresh=True)
            elif get_es_major_version() < 7:
                self.es.update(index='.kibana', doc_type=self.doc_type, id=hit['_id'], body=content, refresh=True)

        if get_es_major_version() >= 6:
            self._kibana_request('/api/kibana/settings/defaultIndex', {'value': 'logstash-*'})
        else:
            print("Warning: unknown ES version, not setting Kibana's defaultIndex", file=sys.stderr)  # noqa: E999

    @staticmethod
    def _get_dashboard_dir():
        dashboard_path = settings.KIBANA_DASHBOARDS_PATH

        kibana6_path = getattr(settings, 'KIBANA6_DASHBOARDS_PATH')
        if get_es_major_version() > 5 and kibana6_path:
            dashboard_path = kibana6_path

        kibana7_path = getattr(settings, 'KIBANA7_DASHBOARDS_PATH')
        if get_es_major_version() > 6 and kibana7_path:
            dashboard_path = kibana7_path

        return dashboard_path

    @staticmethod
    def _get_kibana_files(source, _type):
        files = []
        path = os.path.join(source, _type)
        if not os.path.isdir(path):
            return []
        for _file in os.listdir(path):
            if not _file.endswith('.json'):
                continue
            _file = os.path.join(path, _file)
            files.append(_file)
        return files

    def _get_kibana_subdirfiles(self, _type):
        files = []
        for _dir in os.listdir(self._get_dashboard_dir()):
            src_path = os.path.join(self._get_dashboard_dir(), _dir)
            if os.path.isdir(src_path):
                files += self._get_kibana_files(src_path, _type)
        return files

    def kibana_import_fileobj(self, fileobj):
        tar = tarfile.open(mode='r:bz2', fileobj=fileobj)
        tmpdir = tempfile.mkdtemp()
        tar.extractall(tmpdir)
        tar.close()

        subdirs = os.listdir(tmpdir)
        if len(subdirs) != 1:
            raise Exception('Archive does not appear to contain dashboards, visualizations or searches')
        source = os.path.join(tmpdir, subdirs[0])

        self._create_kibana_mappings()

        count = 0
        for _type in ('search', 'visualization', 'dashboard'):
            source_files = self._get_kibana_files(source, _type)
            count += len(source_files)
            for _file in source_files:
                self._kibana_inject(_type, _file)
        rmtree(tmpdir)

        if count == 0:
            raise Exception('No data loaded')

        return count

    def kibana_clear(self):
        _types = ('search', 'visualization', 'dashboard')
        for _type in _types:
            if get_es_major_version() >= 6:
                query = 'NOT %s.title: SN' % _type
            else:
                query = 'NOT title: SN'

            body = {
                'query': {
                    'query_string': {
                        'query': query
                    }
                }
            }
            self._kibana_remove(_type, body)

    def kibana_reset(self):
        self._create_kibana_mappings()

        if not os.path.isdir(self._get_dashboard_dir()):
            raise Exception('Please make sure Kibana dashboards are installed at %s' % self._get_dashboard_dir())

        if self._get_kibana_subdirfiles('index-pattern') == []:
            raise Exception('Please make sure Kibana dashboards are installed at %s: no index-pattern found' % self._get_dashboard_dir())

        self._kibana_remove('dashboard', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('visualization', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('search', {'query': {'query_string': {'query': 'SN*'}}})
        self._kibana_remove('index-pattern', {'query': {'query_string': {'query': '*'}}})

        for _type in ('index-pattern', 'search', 'visualization', 'dashboard'):
            for _file in self._get_kibana_subdirfiles(_type):
                self._kibana_inject(_type, _file)

        if get_es_major_version() >= 6:
            self._kibana_request('/api/spaces/space', KIBANA6_NAMESPACE)

        self._kibana_set_default_index('logstash-*')

    def get_indexes(self):
        res = self.es.indices.stats()
        indexes = list(res['indices'].keys())
        idxs = list(indexes)

        for idx in idxs:
            if idx.startswith('.kibana'):
                indexes.pop(indexes.index(idx))

        return indexes

    def es_clear(self):
        indexes = self.get_indexes()
        for idx in indexes:
            self.es.indices.delete(index=idx)
        return len(indexes)

    def wait_until_up(self):
        for _ in range(1024):
            try:
                ret = self.es.cluster.health(wait_for_status='green', request_timeout=15 * 60)
                if ret.get('status') == 'green':
                    break
                sleep(10)
            except ESError as e:
                if not isinstance(e.initial_exception, ConnectionError):
                    raise
