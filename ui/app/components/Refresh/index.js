import React from 'react';
import { Button, Space, Select, Tooltip } from 'antd';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { ReloadOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import { observer } from 'mobx-react-lite';
import { useStore } from 'ui/mobx/RootStoreProvider';

const SpaceStyled = styled(Space)`
  margin-left: 10px;
  padding-top: 5px;
`;

const Refresh = () => {
  const { commonStore } = useStore();
  return (
    <SpaceStyled>
      <Select onChange={value => commonStore.setRefreshTime(ReloadPeriodEnum[value])} defaultValue="NONE" style={{ width: 160 }}>
        {Object.keys(ReloadPeriodEnum).map(p => (
          <Select.Option key={p} value={p}>
            {ReloadPeriodEnum[p].title}
          </Select.Option>
        ))}
      </Select>
      <Tooltip title="Reload now">
        <Button onClick={() => commonStore.reload()} icon={<ReloadOutlined />} />
      </Tooltip>
    </SpaceStyled>
  );
};

export default observer(Refresh);
