/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

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
*/

import React, { useEffect, useMemo, useState } from 'react';
import axios from 'axios';
import { Helmet } from 'react-helmet';
import { STAMUS } from 'ui/config';
import { buildQFilter } from 'ui/buildQFilter';
import ErrorHandler from 'ui/components/Error';
import { sections } from 'ui/constants';
import Filters from 'ui/components/Filters';
import buildListParams from 'ui/helpers/buildListParams';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useFilterParams from 'ui/hooks/useFilterParams';
import useAutorun from 'ui/helpers/useAutorun';
import { observer } from 'mobx-react-lite';
import { updateHitsStats } from '../../helpers/updateHitsStats';
import { buildFilter, buildListUrlParams } from '../../helpers/common';
import RuleInList from '../../RuleInList';
import RulePage from '../../RulePage';
import HuntPaginationRow from '../../HuntPaginationRow';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

export const RuleSortFields = [
  {
    id: 'created',
    title: 'Created',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'hits',
    title: 'Alerts',
    isNumeric: true,
    defaultAsc: false,
  },
  {
    id: 'msg',
    title: 'Message',
    isNumeric: false,
    defaultAsc: true,
  },
  {
    id: 'updated',
    title: 'Updated',
    isNumeric: true,
    defaultAsc: false,
  },
];

const defaultListingParams = {
  pagination: {
    page: 1,
    perPage: 10,
    perPageOptions: [10, 20, 50, 100],
  },
  view_type: 'list',
  sort: { id: 'hits', asc: false },
};

const SignaturesPage = () => {
  const { commonStore } = useStore();
  const filterParams = useFilterParams();
  const rulesListConf = buildListParams(JSON.parse(localStorage.getItem('rules_list')), defaultListingParams);

  const [ruleSets, setRuleSets] = useState([]);
  const [signatures, setSignatures] = useState([]);
  const [signaturesCount, setSignaturesCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [listParams, setListParams] = useState(rulesListConf);
  const listUrlParams = buildListUrlParams(listParams);

  const SID = commonStore.filters.find(f => f.id === 'alert.signature_id' && f.negated === false);
  const stringFilters = buildFilter(commonStore.filtersWithAlert, commonStore.systemSettings);
  const fetchData = async () => {
    setLoading(true);
    try {
      const response = await commonStore.fetchSignatures(stringFilters, listUrlParams);
      if (response.ok) {
        if (response.data.results.length > 0) {
          if (!response.data.results[0].timeline_data) {
            const qFilter = buildQFilter(commonStore.filtersWithAlert, commonStore.systemSettings);
            await updateHitsStats(response.data?.results || [], filterParams, rules => setSignatures(rules), qFilter);
          } else {
            setSignatures(
              response.data.results.map(rule => ({
                ...rule,
                timeline_data: undefined,
                timeline: buildTimelineDataSet(rule.timeline_data),
              })),
            );
          }
          setSignaturesCount(response.data.count || 0);
        } else {
          setSignatures([]);
          setSignaturesCount(0);
        }
      }
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('Error retrieving signatures', e);
    }
    setLoading(false);
  };

  useAutorun(fetchData, [stringFilters, listUrlParams, filterParams]);

  useEffect(() => {
    (async () => {
      const response = await commonStore.fetchRuleset();
      if (response.ok) {
        setRuleSets(response.data?.results);
      }
    })();
  }, []);

  const buildTimelineDataSet = tdata => {
    const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
    for (let key = 0; key < tdata.length; key += 1) {
      timeline.columns[0].push(tdata[key].date);
      timeline.columns[1].push(tdata[key].hits);
    }
    return timeline;
  };

  const updateSignatureListState = ({ pagination, sort, view_type: viewType }) => {
    setListParams({ pagination, sort, view_type: viewType });
    localStorage.setItem('rules_list', JSON.stringify({ pagination, sort, view_type: viewType }));
  };

  const sources = useMemo(() => {
    const result = {};
    for (let i = 0; i < commonStore.sources.length; i += 1) {
      const src = commonStore.sources[i];
      result[src.pk] = src;
    }
    return result;
  }, [JSON.stringify(commonStore.sources)]);

  return (
    <div>
      <Helmet>
        <title>{`${STAMUS} - Signatures`}</title>
      </Helmet>
      <ErrorHandler>
        <Filters
          page="RULES_LIST"
          section={sections.GLOBAL}
          queryTypes={['filter', 'rest', 'filter_host_id']}
          filterTypes={['filter', 'rest']}
          sortValues={{ option: listParams.sort.id, direction: listParams.sort.asc ? 'asc' : 'desc' }}
          onSortChange={(option, direction) => {
            updateSignatureListState({
              ...listParams,
              sort: {
                id: option || listParams.sort.id,
                asc: direction ? direction === 'asc' : listParams.sort.asc,
              },
            });
          }}
        />
      </ErrorHandler>

      {!SID && <RuleInList loading={loading} rules={signatures} sources={sources} filterParams={filterParams} rulesets={ruleSets} />}
      <ErrorHandler>
        {!SID && (
          <HuntPaginationRow viewType="list" onPaginationChange={updateSignatureListState} itemsCount={signaturesCount} itemsList={listParams} />
        )}
        {SID && (
          <RulePage
            rule={signatures?.find(s => s.sid === SID.value)}
            sid={SID.value}
            config={listParams}
            filters={commonStore.filters}
            filterParams={filterParams}
            rulesets={ruleSets}
          />
        )}
      </ErrorHandler>
    </div>
  );
};

export default observer(SignaturesPage);
