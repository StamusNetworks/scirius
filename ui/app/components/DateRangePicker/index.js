import React, { useState } from 'react';
import PropTypes from 'prop-types';
import moment from 'moment';
import styled from 'styled-components';
import { Calendar, Button } from 'antd';
import { CalendarHeader } from 'ui/components/CalendarHeader';

const SubmitDate = styled(Button)`
  width: 100%;
  text-align: center;
  border-top: 1px solid #d9d9d9;
`;

const CalendarStyled = styled(Calendar)`
  & .ant-fullcalendar-table {
    height: 200px;
    thead {
      .ant-fullcalendar-column-header {
        .ant-fullcalendar-column-header-inner {
          font-weight: bold;
        }
      }
    }
  }
  & .ant-fullcalendar-value {
    width: 32px;
    padding: 0 8px;
  }
  & .ant-select {
    width: 100%;
  }
`;

const Index = props => {
  const [startDate, setStartDate] = useState(props.selectedFromDate === null ? moment() : moment(props.selectedFromDate));
  const [endDate, setEndDate] = useState(props.selectedToDate === null ? moment() : moment(props.selectedToDate));

  const disabledDate = (type, current) => {
    if (!current) {
      return false;
    }
    if (type === 'startDate' && endDate !== null) {
      return current.valueOf() > endDate.valueOf(); // can not select days before today
    }
    if (type === 'endDate' && startDate !== null) {
      return current.valueOf() < startDate.valueOf(); // can not select days before today
    }
    return false;
  };

  const commonProps = {
    fullscreen: false,
    showWeekNumber: false,
    showOk: false,
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'row' }}>
        <div style={{ marginRight: '10px' }}>
          <CalendarStyled
            defaultValue={moment(startDate)}
            selectedValue={moment(startDate)}
            disabledDate={value => disabledDate('startDate', value)}
            onSelect={a => setStartDate(startDate.date(a.date()))}
            headerRender={({ onChange }) => (
              <CalendarHeader
                value={startDate}
                onChange={a => {
                  onChange(a);
                  setStartDate(startDate.year(a.year()).month(a.month()).hours(a.hours()).minute(a.minute()).seconds(a.seconds()));
                }}
              />
            )}
            {...commonProps}
          />
        </div>
        <div style={{ marginLeft: '10px' }}>
          <CalendarStyled
            defaultValue={moment(endDate)}
            selectedValue={moment(endDate)}
            disabledDate={value => disabledDate('endDate', value)}
            onSelect={a => setEndDate(endDate.date(a.date()))}
            headerRender={({ onChange }) => (
              <CalendarHeader
                value={endDate}
                onChange={a => {
                  onChange(a);
                  setEndDate(endDate.year(a.year()).month(a.month()).hour(a.hour()).minute(a.minute()).second(a.second()));
                }}
              />
            )}
            {...commonProps}
          />
        </div>
      </div>
      <SubmitDate type="primary" onClick={() => props.onOk(startDate, endDate)}>
        Submit
      </SubmitDate>
    </div>
  );
};

Index.propTypes = {
  onOk: PropTypes.any,
  selectedFromDate: PropTypes.any,
  selectedToDate: PropTypes.any,
};

Index.defaultProps = {
  selectedFromDate: null,
  selectedToDate: null,
};

export default Index;
