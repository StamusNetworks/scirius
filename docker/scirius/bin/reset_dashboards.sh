#!/bin/bash

# Copyright(C) 2020 Gabor Seljan
#
# Designed for Debian
#
# This script comes with ABSOLUTELY NO WARRANTY!
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

cd /opt/scirius/

KIBANA_LOADED="/data/kibana_dashboards"

reset_dashboards() {
    for I in $(seq 0 20); do
        echo "Kibana dashboards reset: resetting."
        python manage.py kibana_reset && return 0
        echo "Kibana dashboards reset: Elasticsearch not ready, retrying in 10 seconds."
        sleep 10
    done
    echo "Kibana dashboards reset: Elasticsearch was not ready."
    return -1
}

set_dashboards() {
    while true; do
        ELASTICSEARCH_ADDRESS=$(python manage.py diffsettings --all | grep 'ELASTICSEARCH_ADDRESS' | cut -d"'" -f 2)
        echo "found elastic address : $ELASTICSEARCH_ADDRESS"
        response=$(curl -X PUT "$ELASTICSEARCH_ADDRESS/logstash-stats/_settings" -H 'Content-Type: application/json' -d'
        {
            "index.mapping.total_fields.limit": 2000
        }
    ')

        if [[ $response == *"\"acknowledged\":true"* ]]; then
            echo "max field set"
            break
        else
            echo "settings :"
            echo $response
            if [[ $response == *"index_not_found_exception"* ]]; then
                echo "index dont exist, creating it"
                response=$(curl -X PUT "$ELASTICSEARCH_ADDRESS/logstash-stats" -H 'Content-Type: application/json' -d'
                    {
                    }
                ')
                if [[ $response == *"\"acknowledged\":true"* ]]; then
                    echo "index created"
                else
                    echo "index creation :"
                    echo $response
                fi
            fi
            sleep 5
        fi
    done

    # while true; do
    #     response=$(curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern" -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d'
    #         {
    #             "attributes": {
    #                 "timeFieldName": "timestamp",
    #                 "title": "logstash-*"
    #             }
    #         }
    #     ')
    #     if [[ $response == *"updated"* ]]; then
    #         echo "logstash-* pattern created"
    #         break
    #     else
    #         echo "logstash-* index pattern creation :"
    #         echo $response
    #     fi
    # done

    # while true; do
    #     response=$(curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern" -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d'
    #         {
    #             "attributes": {
    #                 "timeFieldName": "timestamp",
    #                 "title": "*"
    #             }
    #         }
    #     ')
    #     if [[ $response == *"updated"* ]]; then
    #         echo "* index pattern created"
    #         break
    #     else
    #         echo "* index pattern creation :"
    #         echo $response
    #     fi
    # done

    # while true; do
    #     response=$(curl -X POST "$KIBANA_URL/api/saved_objects/index-pattern" -H 'osd-xsrf: true' -H 'Content-Type: application/json' -d'
    #         {
    #             "attributes": {
    #                 "timeFieldName": "timestamp",
    #                 "title": "logstash-alert-*"
    #             }
    #         }
    #     ')
    #     if [[ $response == *"updated"* ]]; then
    #         echo "logstash-alert-* index pattern created"
    #         break
    #     else
    #         echo "logstash-alert-* index pattern creation :"
    #         echo $response
    #     fi
    # done

}

reset_dashboards
# set_dashboards
