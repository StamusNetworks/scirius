import React from 'react';
import { Button, Space, Select, Tooltip } from 'antd';
import PropTypes from 'prop-types';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { ReloadOutlined } from '@ant-design/icons';
import styled from 'styled-components';

const SpaceStyled = styled(Space)`
  margin-left: 10px;
  padding-top: 5px;
`;

const Refresh = ({ onChange, onRefresh }) => (
  <SpaceStyled>
    <Select onChange={value => onChange(ReloadPeriodEnum[value])} style={{ width: 160 }}>
      {Object.keys(ReloadPeriodEnum).map(p => (
        <Select.Option key={p} value={p}>
          {ReloadPeriodEnum[p].title}
        </Select.Option>
      ))}
    </Select>
    <Tooltip title="Reload now">
      <Button onClick={() => onRefresh()} icon={<ReloadOutlined />} />
    </Tooltip>
  </SpaceStyled>
);

export default Refresh;

Refresh.propTypes = {
  onChange: PropTypes.func,
  onRefresh: PropTypes.func,
};
