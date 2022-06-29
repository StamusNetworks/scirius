import { Col, Row, Select, TimePicker } from 'antd';
import React from 'react';
import PropTypes from 'prop-types';

// eslint-disable-next-line no-unused-vars
export const CalendarHeader = ({ value, type, onChange, onTypeChange }) => {
  const start = 0;
  const end = 12;
  const monthOptions = [];

  const current = value.clone();
  const localeData = value.localeData();
  const months = [];
  for (let i = 0; i < 12; i += 1) {
    current.month(i);
    months.push(localeData.monthsShort(current));
  }

  for (let index = start; index < end; index += 1) {
    monthOptions.push(
      <Select.Option className="month-item" key={`${index}`}>
        {months[index]}
      </Select.Option>,
    );
  }
  const month = value.month();

  const year = value.year();
  const options = [];
  for (let i = year - 10; i < year + 10; i += 1) {
    options.push(
      <Select.Option key={i} value={i} className="year-item">
        {i}
      </Select.Option>,
    );
  }
  return (
    <div style={{ paddingBottom: 10, paddingTop: 10 }}>
      <Row type="flex" justify="space-between" gutter={[10, 10]}>
        <Col md={8}>
          <Select
            size="small"
            dropdownMatchSelectWidth={false}
            className="my-year-select"
            onChange={newYear => {
              const now = value.clone().year(newYear);
              onChange(now);
            }}
            value={String(year)}
          >
            {options}
          </Select>
        </Col>
        <Col md={8}>
          <Select
            size="small"
            dropdownMatchSelectWidth={false}
            value={String(month)}
            onChange={selectedMonth => {
              const newValue = value.clone();
              newValue.month(parseInt(selectedMonth, 10));
              onChange(newValue);
            }}
          >
            {monthOptions}
          </Select>
        </Col>
        <Col md={8}>
          <TimePicker format='HH:mm' size="small" onChange={onChange} defaultValue={value} allowClear={false} />
        </Col>
      </Row>
    </div>
  );
};

CalendarHeader.propTypes = {
  value: PropTypes.object,
  type: PropTypes.any,
  onChange: PropTypes.func,
  onTypeChange: PropTypes.func,
};
