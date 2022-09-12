import React, { useState, useEffect } from 'react';
import { connect, useDispatch, useSelector } from 'react-redux';
import PropTypes from 'prop-types';
import { Button, Modal } from 'antd';
import { QuestionOutlined, ReadOutlined } from '@ant-design/icons';
import styled from 'styled-components';
import LoadingIndicator from 'ui/components/LoadingIndicator';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';

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
  background-image: url(/static/bundles/media/bg-modal-about-pf.19515f0d.png);
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

const HelpMenu = ({ isEnterpriseEdition }) => {
  const dispatch = useDispatch();
  const [visible, setVisible] = useState(false);

  const { data: context, request: contextRequest } = useSelector(selectors.makeSelectContext());
  const { loading: contextLoading } = contextRequest;

  const { data, request: sourceRequest } = useSelector(selectors.makeSelectSource());
  const [source] = data;
  const { loading: sourceLoading } = sourceRequest;

  useEffect(() => {
    if (visible) {
      dispatch(actions.getContextRequest());
      dispatch(actions.getSource());
    }
  }, [visible]);

  return (
    <Wrapper>
      <AboutModal
        title=" "
        visible={visible}
        onOk={() => setVisible(false)}
        onCancel={() => setVisible(false)}
        footer={
          <div className="about-footer">
            <img src="/static/bundles/media/stamus_logo.4bca432d.png" alt="SCS Logo" />
          </div>
        }
      >
        <H1>{isEnterpriseEdition ? context.title : 'Scirius Community Edition'}</H1>
        <VersionTitle>
          {isEnterpriseEdition ? (
            'Versions'
          ) : (
            <div>
              <strong>Version </strong>
              <span>Scirius CE v{contextLoading ? loadingIndicator : /\d+\.\d+\.\d+/.exec(context.version)}</span>
            </div>
          )}
        </VersionTitle>
        {isEnterpriseEdition && (
          <VersionsList>
            <Version>
              <strong>Scirius Security Platform:</strong> {contextLoading ? loadingIndicator : context.version}
            </Version>
            <Version>
              <strong>Stamus Threat Intelligence:</strong>
              {sourceLoading ? loadingIndicator : source.version ? ` v${source.version}` : <i>rules update needed</i>}
            </Version>
          </VersionsList>
        )}
        <CopyRight>Copyright 2014-{new Date().getFullYear()}, Stamus Networks</CopyRight>
      </AboutModal>

      <Item
        block
        type="link"
        icon={<ReadOutlined />}
        onClick={() => window.open(`${isEnterpriseEdition ? '/static/doc/stamus-security-platform/security-posture.html' : '/static/doc/hunt.html'}`)}
      >
        User manual
      </Item>
      <Item block type="link" icon={<QuestionOutlined />} onClick={() => setVisible(true)}>
        {isEnterpriseEdition ? 'About SCS' : 'About Scirius CE'}
      </Item>
    </Wrapper>
  );
};

HelpMenu.propTypes = {
  isEnterpriseEdition: PropTypes.bool,
};

const mapStateToProps = ({ global }) => ({ isEnterpriseEdition: !!global.ee });

export default connect(mapStateToProps)(HelpMenu);
