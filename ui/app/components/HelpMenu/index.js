import React, { useState, useEffect } from 'react';
import { Button, Modal } from 'antd';
import { QuestionOutlined, ReadOutlined } from '@ant-design/icons';
import { observer } from 'mobx-react-lite';
import styled from 'styled-components';
import moment from 'moment';
import constants from 'ui/constants';
import LoadingIndicator from 'ui/components/LoadingIndicator';
import { useStore } from 'ui/mobx/RootStoreProvider';
import useEnterprise from 'ui/hooks/useEnterprise';
const { DATE_FORMAT } = constants;

const Wrapper = styled.div`
  display: grid;
  grid-gap: 10px;
  width: 240px;
`;

const Item = styled(Button)`
  display: grid;
  grid-template-columns: min-content 1fr;
  align-items: center;
  padding: 0;
  border: none;

  &:hover {
    background: #f0f2f5;
  }
  &:active {
    background: #bcccd1;
  }
  &:hover svg {
    color: rgba(0, 0, 0, 0.85);
  }

  & > span {
    display: flex;
    padding: 5px 8px;
    margin: 0px !important;
    color: rgba(0, 0, 0, 0.85);
  }

  & svg {
    height: 22px;
    width: 22px;
    color: #d9d9d9;
    transition: all 0.6s;
  }
`;

const AboutModal = styled(Modal)`
  background-color: #292e34;
  background-image: url(/static/rules/about-modal-pf.png);
  background-position: right bottom;
  background-repeat: no-repeat;
  padding-bottom: 0px !important;
  width: 600px !important;

  .ant-modal-footer {
    padding: 0px !important;
  }
  .ant-modal-header,
  .ant-modal-footer,
  .ant-modal-content {
    box-shadow: none;
    border-bottom: 0px;
    border-top: 0px;
    background: transparent !important;
  }
  .ant-modal-body {
    padding: 40px 90px 30px;
  }
  .about-footer {
    background: #fff;
    padding: 15px 20px;
  }
  .ant-modal-close {
    color: #fff !important;
  }
`;

const H1 = styled.h1`
  color: #fff;
  font-size: 24px;
`;

const Version = styled.li`
  color: #fff;
  padding: 10px 0px;
  font-size: 12px;
`;

const VersionTitle = styled.li`
  color: #fff;
  font-style: italic;
  padding: 10px 0px;
  font-size: 12px;
`;

const CopyRight = styled.div`
  color: #fff;
  padding: 10px 0px;
  font-size: 12px;
`;

const VersionsList = styled.ul`
  padding: 0 0 0 12px;
  margin: 0;
`;
const loadingIndicator = <LoadingIndicator style={{ display: 'inline-block', margin: '0', height: '20px' }} />;

const HelpMenu = () => {
  const { commonStore } = useStore();
  const isEnterpriseEdition = useEnterprise();
  const [visible, setVisible] = useState(false);
  const [context, setContext] = useState(null);
  const [contextLoading, setContextLoading] = useState(false);

  useEffect(() => {
    (async () => {
      setContextLoading(true);
      const response = await commonStore.fetchContext();
      if (response.ok) {
        setContext(response.data);
      }
      setContextLoading(false);
    })();
  }, []);

  let labelSCS = '';
  let version = 0;
  if (!contextLoading && context && context.version) {
    if (isEnterpriseEdition) {
      [labelSCS] = /(\w+ ){2}(\w+)/.exec(context.version);
    }
    version = /\d+\.\d+\.\d+/.exec(context.version);
  }

  const [source] = commonStore.sources;

  return (
    <Wrapper>
      <AboutModal
        title=" "
        visible={visible}
        onOk={() => setVisible(false)}
        onCancel={() => setVisible(false)}
        footer={
          <div className="about-footer">
            <img src="/static/rules/stamus_logo.png" alt="SCS Logo" />
          </div>
        }
      >
        {!contextLoading && <H1>{isEnterpriseEdition ? context?.title : 'Scirius Community Edition'}</H1>}
        <VersionTitle>
          {isEnterpriseEdition ? (
            'Versions'
          ) : (
            <div>
              <strong>Version </strong>
              <span>Scirius CE v{contextLoading ? loadingIndicator : version}</span>
            </div>
          )}
        </VersionTitle>
        {isEnterpriseEdition && (
          <VersionsList>
            <Version>
              <strong>{contextLoading ? loadingIndicator : `${labelSCS}:`}</strong>
              {` v${version}`}
            </Version>
            <Version>
              <strong>Stamus Threat Intelligence: </strong>
              {source?.version ? `v${source.version}` : <i>rules update needed</i>}
              {source?.updated_date && ` (updated at ${moment(source.updated_date).format(DATE_FORMAT)})`}
            </Version>
          </VersionsList>
        )}
        <CopyRight>Copyright 2014-2023, Stamus Networks</CopyRight>
      </AboutModal>

      <Item
        block
        type="link"
        icon={<ReadOutlined />}
        onClick={() => window.open(`${isEnterpriseEdition ? '/static/doc/stamus-central-server/security-posture.html' : '/static/doc/hunt.html'}`)}
      >
        User manual
      </Item>
      <Item block type="link" icon={<QuestionOutlined />} onClick={() => setVisible(true)}>
        {isEnterpriseEdition ? 'About SCS' : 'About Scirius CE'}
      </Item>
    </Wrapper>
  );
};
export default observer(HelpMenu);
