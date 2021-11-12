import React  from 'react';
import PropTypes from 'prop-types';
import { Row, Tabs, Radio, notification } from 'antd';
import styled from 'styled-components';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { bindActionCreators, compose } from 'redux';
import DateRangePicker from 'ui/components/DateRangePicker';
import selectors from 'ui/containers/App/selectors';
import actions from 'ui/containers/App/actions';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
// eslint-disable-next-line import/named
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
}) => {

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
                    value={PeriodEnum[p].title}
                    checked={p === duration.title}
                    key={p}
                    name={PeriodEnum[p].title}
                    onClick={() => {
                      setDuration(p);
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
};

const mapStateToProps = createStructuredSelector({
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  duration: selectors.makeSelectDuration(),
  timePicker: selectors.makeSelectTimePicker(),
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
