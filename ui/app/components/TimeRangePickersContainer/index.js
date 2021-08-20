import React, { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { Row, Tabs, Radio, notification } from 'antd';
import styled from 'styled-components';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { bindActionCreators, compose } from 'redux';
import moment from 'moment';
import DateRangePicker from 'ui/components/DateRangePicker';
import selectors from 'ui/containers/App/selectors';
import actions from 'ui/containers/App/actions';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
import request from 'ui/utils/request';
// eslint-disable-next-line import/named
import { RULES_URL } from 'ui/config';
const { TabPane } = Tabs;
const RadioButton = Radio.Button;
const RadioGroup = Radio.Group;

const PickersWrapper = styled.div`
  width: 600px;
  display: flex;
  flex-direction: column;
`;

const QuicksWrapper = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
`;

const TimeRangePickersContainer = ({
  startDate,
  endDate,
  duration,
  setDuration,
  setTimeSpan,
  timePicker,
  filtersParam,
  reloadData,
}) => {
  const [minTime, setMinTime] = useState(moment(0)); // used by the `All` timerange
  const [maxTime, setMaxTime] = useState(moment(0)); // used by the `All` timerange

  let error = '';

  useEffect(() => {
    (async () => {
      const timeRange = await request(`${RULES_URL}/es/alerts_timerange/?${filtersParam}`);
      if (timeRange.min_timestamp && timeRange.max_timestamp) {
        setMinTime(moment(timeRange.min_timestamp));
        setMaxTime(moment(timeRange.max_timestamp));
      }
    })();
  }, [filtersParam, reloadData.now]);

  const validateTimeSpan = (startDateIn, endDateIn) => {
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

  return (
    <PickersWrapper>
      <Tabs defaultActiveKey={timePicker.toString()} size="small" className="tabs-time-frames">
        <TabPane tab="Quick" key="0">
          <Row type="flex" justify="center" style={{ padding: '40px 0px' }}>
            <QuicksWrapper>
              <strong>Last:</strong>
              <RadioGroup defaultValue="a" size="default">
                {Object.keys(PeriodEnum).map(p => (
                  <RadioButton
                    value={PeriodEnum[p].seconds}
                    checked={p === duration}
                    key={p}
                    name={PeriodEnum[p].title}
                    onClick={() => {
                      if (p !== PeriodEnum[p].seconds) {
                        // handling the case when preset duration is used
                        setDuration(p);
                      } else {
                        // handling the case when custom duration `All` is used
                        if (!minTime || !maxTime) return;
                        setDuration(p);
                        validateTimeSpan(minTime, maxTime);
                      }
                    }}
                  >
                    {PeriodEnum[p].name}
                  </RadioButton>
                ))}
              </RadioGroup>
            </QuicksWrapper>
          </Row>
        </TabPane>
        <TabPane tab="Absolute" key="1">
          <DateRangePicker selectedFromDate={startDate} selectedToDate={endDate} onOk={validateTimeSpan} />
        </TabPane>
      </Tabs>
    </PickersWrapper>
  );
};

TimeRangePickersContainer.propTypes = {
  startDate: PropTypes.any,
  endDate: PropTypes.any,
  duration: PropTypes.any,
  setDuration: PropTypes.any,
  setTimeSpan: PropTypes.any,
  timePicker: PropTypes.any,
  filtersParam: PropTypes.any,
  reloadData: PropTypes.object,
};

const mapStateToProps = createStructuredSelector({
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  duration: selectors.makeSelectDuration(),
  timePicker: selectors.makeSelectTimePicker(),
  filtersParam: selectors.makeSelectFiltersParam(),
  reloadData: selectors.makeSelectReload(),
});

export const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setTimeSpan: actions.setTimeSpan,
      setDuration: actions.setDuration,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);

export default compose(withConnect)(TimeRangePickersContainer);
