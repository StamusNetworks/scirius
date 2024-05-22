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

import { Switch } from 'antd';
import axios from 'axios';
import { toJS } from 'mobx';
import { observer } from 'mobx-react-lite';
import { Helmet } from 'react-helmet';
import styled from 'styled-components';

import { buildQFilter } from 'ui/buildQFilter';
import ErrorHandler from 'ui/components/Error';
import Filters from 'ui/components/Filters';
import { STAMUS } from 'ui/config';
import buildListParams from 'ui/helpers/buildListParams';
import useAutorun from 'ui/helpers/useAutorun';
import useFilterParams from 'ui/hooks/useFilterParams';
import { useStore } from 'ui/mobx/RootStoreProvider';

import { buildListUrlParams } from '../../helpers/common';
import { updateHitsStats } from '../../helpers/updateHitsStats';
import HuntPaginationRow from '../../HuntPaginationRow';
import RuleInList from '../../RuleInList';
import RulePage from '../../RulePage';

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

const AlertsMinOneToggle = styled.div`
  display: grid;
  grid-template-columns: repeat(2, max-content);
  grid-gap: 10px;
  align-items: center;
  justify-content: end;
  margin: 10px;
`;

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

  const SIDs = commonStore.filters.filter(f => f.id === 'alert.signature_id' && f.negated === false && !f.suspended);
  const SID = SIDs.length === 1 ? SIDs[0] : null;

  const updateSignatureListState = ({ pagination, sort }) => {
    setListParams({ pagination, sort });
    localStorage.setItem('rules_list', JSON.stringify({ pagination, sort }));
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      const response = await commonStore.fetchSignatures(listUrlParams);
      if (response.ok) {
        if (response.data.results.length > 0) {
          if (!response.data.results[0].timeline_data) {
            const qFilter = buildQFilter([...toJS(commonStore.filters), toJS(commonStore.alert)], commonStore.systemSettings);
            await updateHitsStats(
              response.data?.results || [],
              filterParams,
              rules => {
                setSignatures(rules);
                setLoading(false);
              },
              qFilter,
            );
            setSignaturesCount(response.data.count || 0);
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
      } else {
        updateSignatureListState({ pagination: { ...listParams.pagination, page: 1 }, sort: listParams.sort });
      }
      setLoading(false);
    } catch (e) {
      setLoading(false);
      // eslint-disable-next-line no-console
      console.error('Error retrieving signatures', e);
    }
  };

  useAutorun(fetchData, [listUrlParams, commonStore.withAlerts]);

  useEffect(() => {
    updateSignatureListState({ pagination: { ...listParams.pagination, page: 1 }, sort: listParams.sort });
  }, [commonStore.withAlerts]);

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
          filterTypes={['SIGNATURE', 'EVENT', 'HOST']}
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

      <AlertsMinOneToggle>
        <Switch
          data-test="alertsMinOne-switch"
          size="small"
          checkedChildren="ON"
          unCheckedChildren="OFF"
          checked={commonStore.withAlerts}
          onChange={value => {
            commonStore.withAlerts = value;
          }}
        />
        <span>Show only with alerts</span>
      </AlertsMinOneToggle>

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
