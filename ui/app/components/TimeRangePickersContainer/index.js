import React from 'react';

import { Row, Col } from 'antd';
import { observer } from 'mobx-react-lite';
import { useDispatch } from 'react-redux';
import styled from 'styled-components';

import DateRangePicker from 'ui/components/DateRangePicker';
import PeriodsList from 'ui/components/PeriodsList';
import Refresh from 'ui/components/Refresh';
import UITabs from 'ui/components/UIElements/UITabs';
import actions from 'ui/containers/App/actions';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { useStore } from 'ui/mobx/RootStoreProvider';

const PickersWrapper = styled.div`
  width: 600px;
  display: flex;
  flex-direction: column;
`;

const Label = styled.div`
  color: #979797;
`;

const TimeRangePickersContainer = () => {
  const { commonStore } = useStore();
  const dispatch = useDispatch();

  const hours = {
    H1: PeriodEnum.H1,
    H6: PeriodEnum.H6,
    H24: PeriodEnum.H24,
  };

  const days = {
    D2: PeriodEnum.D2,
    D7: PeriodEnum.D7,
    D30: PeriodEnum.D30,
  };

  const more = {
    Y1: PeriodEnum.Y1,
    All: PeriodEnum.All,
    Auto: PeriodEnum.Auto,
  };

  return (
    <PickersWrapper>
      <UITabs
        defaultActiveKey={commonStore.timeRangeType}
        size="small"
        className="tabs-time-frames"
        tabs={[
          {
            key: 'relative',
            tab: 'Presets',
            children: (
              <Row type="flex" justify="center">
                <Col md={5}>
                  <Label>Hours</Label>
                  <PeriodsList
                    options={hours}
                    value={commonStore.relativeType}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      dispatch(actions.setDuration(p));
                    }}
                  />
                </Col>
                <Col md={5}>
                  <Label>Days</Label>
                  <PeriodsList
                    options={days}
                    value={commonStore.relativeType}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      dispatch(actions.setDuration(p));
                    }}
                  />
                </Col>
                <Col md={5}>
                  <Label>More</Label>
                  <PeriodsList
                    options={more}
                    value={commonStore.relativeType}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      dispatch(actions.setDuration(p));
                    }}
                  />
                </Col>
                <Col md={9}>
                  <Label>Refresh Interval</Label>
                  <Refresh />
                </Col>
              </Row>
            ),
          },
          {
            key: 'absolute',
            tab: 'Date & Time Range',
            children: (
              <DateRangePicker
                selectedFromDate={commonStore.startDate}
                selectedToDate={commonStore.endDate}
                onOk={(startDate, endDate) => {
                  commonStore.setAbsoluteTimeRange(startDate, endDate);
                  dispatch(actions.setTimeSpan(startDate, endDate));
                }}
              />
            ),
          },
        ]}
      />
    </PickersWrapper>
  );
};

export default observer(TimeRangePickersContainer);
