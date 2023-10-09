import React, { useState } from 'react';

import { Calendar, Button, notification } from 'antd';
import { observer } from 'mobx-react-lite';
import moment from 'moment';
import styled from 'styled-components';

import { CalendarHeader } from 'ui/components/CalendarHeader';
import { useStore } from 'ui/mobx/RootStoreProvider';

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

const DateRangePicker = () => {
  const { commonStore } = useStore();
  const [startDate, setStartDate] = useState(moment());
  const [endDate, setEndDate] = useState(moment());

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
            defaultValue={startDate}
            selectedValue={startDate}
            disabledDate={value => disabledDate('startDate', value)}
            onSelect={value => setStartDate(value)}
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
            defaultValue={endDate}
            selectedValue={endDate}
            disabledDate={value => disabledDate('endDate', value)}
            onSelect={value => setEndDate(value)}
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
      <SubmitDate
        type="primary"
        onClick={() => {
          if (endDate.unix() < startDate.unix()) {
            notification.error({
              message: 'Invalid data',
              duration: 2,
              description: 'End date must not be greater than start date',
              placement: 'topLeft',
            });
          } else {
            commonStore.setAbsoluteTimeRange(startDate.unix(), endDate.unix());
          }
        }}
      >
        Submit
      </SubmitDate>
    </div>
  );
};

export default observer(DateRangePicker);
