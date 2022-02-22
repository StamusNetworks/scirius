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

  & label {
    color: rgba(0, 0, 0, 0.85) !important;
    border: 1px #bcccd1 solid !important;
    margin-right: 1px;
  }

  & label:hover {
    background: #f0f2f5;
    border: 1px #005792 solid !important;
  }

  & .ant-radio-button-wrapper-checked {
    background: #bcccd1 !important;
    border-color: #005792 !important;
  }

  .ant-radio-button-wrapper-checked::before, .ant-radio-button-wrapper::before {
    background-color: transparent;
    border-color: transparent;
  }
`;

const TimeRangePickersContainer = ({
  startDate,
  endDate,
  duration,
  setDuration,
  setTimeSpan,
  timePicker,
  timeSpan,
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
              <h4><strong>Last:</strong></h4>
              <RadioGroup size="default" value={duration}>
                {Object.keys(PeriodEnum).map(p => (
                  <RadioButton
                    disabled={timeSpan.disableAll && PeriodEnum[p].name === 'All'}
                    value={p}
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
  timeSpan: PropTypes.any,
};

const mapStateToProps = createStructuredSelector({
  startDate: selectors.makeSelectStartDate(),
  endDate: selectors.makeSelectEndDate(),
  duration: selectors.makeSelectDuration(),
  timePicker: selectors.makeSelectTimePicker(),
  timeSpan: selectors.makeSelectTimespan(),
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
