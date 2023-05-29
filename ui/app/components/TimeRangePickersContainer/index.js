import React from 'react';
import PropTypes from 'prop-types';
import { Row, notification, Col, Button } from 'antd';
import styled from 'styled-components';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { bindActionCreators, compose } from 'redux';
import DateRangePicker from 'ui/components/DateRangePicker';
import selectors from 'ui/containers/App/selectors';
import actions from 'ui/containers/App/actions';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import UITabs from 'ui/components/UIElements/UITabs';
import PeriodsList from 'ui/components/PeriodsList';
import Refresh from 'ui/components/Refresh';
import { useStore } from 'ui/mobx/RootStoreProvider';
import { observer } from 'mobx-react-lite';

const PickersWrapper = styled.div`
  width: 600px;
  display: flex;
  flex-direction: column;
`;

const Label = styled.div`
  color: #979797;
`;

const TimeRangePickersContainer = ({ startDate, endDate, duration, setDuration, setTimeSpan, timePicker, setReload, doReload, reloadPeriod }) => {
  const { commonStore } = useStore();
  const validateTimeSpan = (startDateIn, endDateIn) => {
    let error = '';
    if (startDateIn.unix() === endDateIn.unix()) {
      error = 'Selecting the same start and end date is not allowed.';
    } else if (startDateIn.unix() > endDateIn.unix()) {
      error = 'Start date could not be greater than end date.';
    } else {
      setTimeSpan(startDateIn, endDateIn);
    }

    if (error.length > 0) {
      notification.error({
        message: 'Invalid time span',
        description: <React.Fragment>{error}</React.Fragment>,
        duration: 4.5,
        style: {
          marginTop: 500,
        },
        placement: 'topRight',
      });
    }
  };

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
    All: PeriodEnum.ALL,
  };

  return (
    <PickersWrapper>
      <Button onClick={() => commonStore.addFilter({ a: 'b' })}>ids</Button>
      <UITabs
        defaultActiveKey={timePicker.toString()}
        size="small"
        className="tabs-time-frames"
        tabs={[
          {
            key: '0',
            tab: 'Presets',
            children: (
              <Row type="flex" justify="center">
                <Col md={5}>
                  <Label>Hours</Label>
                  <PeriodsList
                    options={hours}
                    value={duration}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      setDuration(p);
                    }}
                  />
                </Col>
                <Col md={5}>
                  <Label>Days</Label>
                  <PeriodsList
                    options={days}
                    value={duration}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      setDuration(p);
                    }}
                  />
                </Col>
                <Col md={5}>
                  <Label>More</Label>
                  <PeriodsList
                    options={more}
                    value={duration}
                    onChange={p => {
                      commonStore.setRelativeTimeRange(p);
                      setDuration(p);
                    }}
                  />
                </Col>
                <Col md={9}>
                  <Label>Refresh Interval</Label>
                  <Refresh onChange={value => setReload(value)} onRefresh={() => doReload()} value={reloadPeriod.period.seconds} />
                </Col>
              </Row>
            ),
          },
          {
            key: '1',
            tab: 'Date & Time Range',
            children: <DateRangePicker selectedFromDate={startDate} selectedToDate={endDate} onOk={validateTimeSpan} />,
          },
        ]}
      />
    </PickersWrapper>
  );
};

TimeRangePickersContainer.propTypes = {
  startDate: PropTypes.any,
  endDate: PropTypes.any,
  duration: PropTypes.any,
  setDuration: PropTypes.any,
  setTimeSpan: PropTypes.any,
  setReload: PropTypes.any,
  doReload: PropTypes.any,
  timePicker: PropTypes.any,
  reloadPeriod: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  duration: selectors.makeSelectDuration(),
  timePicker: selectors.makeSelectTimePicker(),
  reloadPeriod: selectors.makeSelectReload(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setTimeSpan: actions.setTimeSpan,
      setDuration: actions.setDuration,
      setReload: actions.setReload,
      doReload: actions.doReload,
    },
    dispatch,
  );

const withConnect = connect(mapStateToProps, mapDispatchToProps);

export default compose(withConnect)(observer(TimeRangePickersContainer));
