import React, { useState } from 'react';

import PropTypes from 'prop-types';

import { buildQFilter } from 'ui/buildQFilter';
import { Timeline, XAxisLabelDateTime } from 'ui/components/Charts';
import { getTimelineData } from 'ui/components/Charts/Timeline/helpers';
import notify from 'ui/helpers/notify';
import useAutorun from 'ui/helpers/useAutorun';
import { useStore } from 'ui/mobx/RootStoreProvider';

import * as Style from './style';

export const DashboardTimeline = ({ filterParams, chartTarget, filters, systemSettings, eventTypes }) => {
  const { esStore } = useStore();
  const [loading, setLoading] = useState(true);
  const [chart, setChart] = useState({});

  const fetchData = async () => {
    try {
      const qfilter = buildQFilter(filters, systemSettings);
      const res = await esStore.fetchTimeline(chartTarget, qfilter);
      setChart(getTimelineData(res, chartTarget));
      setLoading(false);
    } catch (e) {
      notify('Error fetching data', e);
      setLoading(false);
    }
  };

  useAutorun(fetchData, [filterParams, chartTarget, filters, systemSettings, eventTypes]);

  if (loading) {
    return <div>Loading...</div>;
  }

  return (
    <Style.Card flex>
      <Timeline chart={chart} stacked XAxisLabel={XAxisLabelDateTime} />
    </Style.Card>
  );
};

DashboardTimeline.propTypes = {
  filterParams: PropTypes.object.isRequired,
  chartTarget: PropTypes.string.isRequired,
  filters: PropTypes.array.isRequired,
  systemSettings: PropTypes.object.isRequired,
  eventTypes: PropTypes.array.isRequired,
};
