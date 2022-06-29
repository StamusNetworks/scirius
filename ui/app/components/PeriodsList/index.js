import React from 'react';
import styled from 'styled-components';
import { Radio } from 'antd';
import { createStructuredSelector } from 'reselect';
import { connect } from 'react-redux';
import { compose } from 'redux';
import PropTypes from 'prop-types';
import selectors from 'ui/containers/App/selectors';
import { PeriodEnum } from 'ui/maps/PeriodEnum';
const RadioButton = Radio.Button;
const RadioGroup = Radio.Group;

const RadioGroupStyled = styled(RadioGroup)`
  display: flex;
  flex-direction: column;
  padding-right: 20px;

  .selected {
    background-color: #005792;
    color: #FFF;
    border-radius: 5px;
  }

  .ant-radio-button-wrapper:not(:first-child)::before {
    background: none;
  }
`

const RadioButtonStyled = styled(RadioButton)`
  border: 0 !important;
  margin: 2px 0;
  border-radius: 5px !important;
  &:hover {
    background-color: #005792;
    color: #FFF;
  }
`

const PeriodsList = ({ options, value, timeSpan, onChange }) => (
    <RadioGroupStyled size="default" value={value}>
      {Object.keys(options).map(p => (
        <RadioButtonStyled
          disabled={timeSpan.disableAll && PeriodEnum[p].name === 'All'}
          value={p}
          key={p}
          name={PeriodEnum[p].title}
          className={p === value ? 'selected' : ''}
          onClick={() => onChange(p)}
        >
          {PeriodEnum[p].name}
        </RadioButtonStyled>
      ))}
    </RadioGroupStyled>
  )

PeriodsList.propTypes = {
  options: PropTypes.object,
  value: PropTypes.any,
  timeSpan: PropTypes.any,
  onChange: PropTypes.func,
}

const mapStateToProps = createStructuredSelector({
  timeSpan: selectors.makeSelectTimespan(),
});


const withConnect = connect(
  mapStateToProps,
);

export default compose(withConnect)(PeriodsList);
