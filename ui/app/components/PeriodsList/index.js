import React from 'react';

import { Radio } from 'antd';
import { observer } from 'mobx-react-lite';
import PropTypes from 'prop-types';
import styled from 'styled-components';

import { PeriodEnum } from 'ui/maps/PeriodEnum';
import { useStore } from 'ui/mobx/RootStoreProvider';

const RadioButton = Radio.Button;
const RadioGroup = Radio.Group;

const RadioGroupStyled = styled(RadioGroup)`
  display: flex;
  flex-direction: column;
  padding-right: 20px;

  .selected {
    background-color: #005792;
    color: #fff;
    border-radius: 5px;
  }

  .ant-radio-button-wrapper:not(:first-child)::before {
    background: none;
  }
`;

const RadioButtonStyled = styled(RadioButton)`
  border: 0 !important;
  margin: 2px 0;
  border-radius: 5px !important;
  &:hover {
    background-color: #005792;
    color: #fff;
  }
`;

const PeriodsList = ({ options, value, onChange }) => {
  const { commonStore } = useStore();
  return (
    <RadioGroupStyled size="default" value={value}>
      {Object.keys(options).map(p => (
        <RadioButtonStyled
          disabled={commonStore.disableAll && PeriodEnum[p].name === 'All'}
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
  );
};

PeriodsList.propTypes = {
  options: PropTypes.object,
  value: PropTypes.any,
  onChange: PropTypes.func,
};

export default observer(PeriodsList);
