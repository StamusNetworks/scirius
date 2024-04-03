import React, { useState, useMemo } from 'react';

import { toJS } from 'mobx';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';

import { buildQFilter } from 'ui/buildQFilter';
import { BarChart, XAxisLabelDateTime } from 'ui/components/Charts';
import { getTimelineData } from 'ui/components/Charts/helpers';
import notify from 'ui/helpers/notify';
import useAutorun from 'ui/helpers/useAutorun';
import useFilterParams from 'ui/hooks/useFilterParams';
import useResizeObserver from 'ui/hooks/useResizeObserver';
import { useStore } from 'ui/mobx/RootStoreProvider';
import Filter from 'ui/utils/Filter';

import * as Style from './style';

export const Timeline = observer(({ sid }) => {
  const { commonStore, esStore } = useStore();
  const [ref, width] = useResizeObserver();
  const filterParams = useFilterParams();
  // Memoize filters to avoid unnecessary re-renders
  const filters = useMemo(
    // Group filters from store, alert and new filter for signature_id
    () => [...commonStore.filters.map(f => f.toJSON()), toJS(commonStore.alert), new Filter('alert.signature_id', sid).toJSON()],
    [],
  );
  const { systemSettings } = commonStore;

  const [loading, setLoading] = useState(true);
  const [chart, setChart] = useState({});
  const fetchData = async () => {
    try {
      setLoading(true);
      const qfilter = buildQFilter(filters, systemSettings);
      const res = await esStore.fetchTimeline(true, qfilter);
      setChart(getTimelineData(res, true));
      setLoading(false);
    } catch (e) {
      notify('Error fetching timeline data', e);
      setLoading(false);
    }
  };

  useAutorun(fetchData, [filterParams, filters, systemSettings]);

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <Style.Card flex>
      <div ref={ref}>
        <BarChart chart={chart} height={200} width={width} XAxisLabel={XAxisLabelDateTime} />
      </div>
    </Style.Card>
  );
});

Timeline.propTypes = {
  sid: PropTypes.number.isRequired,
};
