/* eslint-disable react/no-this-in-sfc */
import React, { useRef } from 'react';
import { Button, Space, Select, Tooltip, Progress } from 'antd';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { ReloadOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import { observer, useLocalObservable } from 'mobx-react-lite';
import { useStore } from 'ui/mobx/RootStoreProvider';

const SpaceStyled = styled(Space)`
  margin-left: 10px;
  padding-top: 5px;
`;
const Refresh = () => {
  const { commonStore } = useStore();

  const timer = useLocalObservable(() => ({
    secondsPassed: 0,
    increaseTimer() {
      if (this.secondsPassed < commonStore.refreshTime) {
        this.secondsPassed += 1000;
        if (this.secondsPassed === commonStore.refreshTime) {
          commonStore.reload();
        }
      } else {
        this.secondsPassed = 0;
      }
    },
    resetTimer() {
      this.secondsPassed = 0;
    },
  }));

  const handle = useRef(null);

  return (
    <>
      <SpaceStyled>
        <Select
          onChange={value => {
            if (value === 'NONE') {
              clearInterval(handle.current);
              timer.resetTimer();
              commonStore.setRefreshTime(null);
            } else {
              commonStore.setRefreshTime(ReloadPeriodEnum[value].seconds);
              clearInterval(handle.current);
              if (timer.secondsPassed > 0) {
                timer.resetTimer();
              }
              handle.current = setInterval(timer.increaseTimer, 1000);
            }
          }}
          defaultValue="NONE"
          style={{ width: 160 }}
        >
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
      {commonStore.refreshTime && (
        <>
          <Progress percent={(timer.secondsPassed / commonStore.refreshTime) * 100} size={[300, 20]} showInfo={false} strokeColor="#005792" />
          {commonStore.refreshTime > 0 && timer.secondsPassed < commonStore.refreshTime && (
            <>{(commonStore.refreshTime - timer.secondsPassed) / 1000} seconds left...</>
          )}
          {commonStore.refreshTime - timer.secondsPassed === 0 && <span>Refreshing...</span>}
        </>
      )}
    </>
  );
};

export default observer(Refresh);
