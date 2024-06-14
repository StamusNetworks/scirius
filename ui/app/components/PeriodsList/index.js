import React from 'react';

import { Radio, Tooltip } from 'antd';
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
  border-radius: 5px;
  .ant-radio-button-wrapper::before {
    background: none;
    width: 0 !important;
  }
  .ant-radio-button-wrapper,
  .ant-radio-button-wrapper:first-child,
  .ant-radio-button-wrapper:last-child {
    border: 0;
    border-radius: 5px;
  }
`;

const RadioButtonStyled = styled(RadioButton)`
  border: 0;
  margin: 2px 0;

  &:hover {
    background-color: ${p => (!p.disabled ? '#005792' : '')};
    color: ${p => (!p.disabled ? '#fff' : '')};
  }

  background-color: ${p => (p.selected ? '#005792' : '')} !important;
  color: ${p => (p.selected ? '#fff' : '')} !important;
`;

const PeriodsList = ({ options, value, onChange }) => {
  const { commonStore } = useStore();
  return (
    <RadioGroupStyled size="default" value={value}>
      {Object.keys(options).map(p => {
        const isDisabled = commonStore.disableAll && PeriodEnum[p].name === 'Auto';
        return (
          <Tooltip title={isDisabled ? 'This option is disabled because of invalid min/max time range' : null} placement="bottom">
            <RadioButtonStyled disabled={isDisabled} value={p} key={p} name={PeriodEnum[p].title} selected={p === value} onClick={() => onChange(p)}>
              {PeriodEnum[p].name}
            </RadioButtonStyled>
          </Tooltip>
        );
      })}
    </RadioGroupStyled>
  );
};

PeriodsList.propTypes = {
  options: PropTypes.object,
  value: PropTypes.any,
  onChange: PropTypes.func,
};

export default observer(PeriodsList);
