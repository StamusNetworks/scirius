import React from 'react';

import { Modal, Tabs } from 'antd';
import PropTypes from 'prop-types';

import { SigContent } from '../ExpandedSignature';

const RuleContentModal = props => {
  const ruleVersions = Object.keys(props.rule_status.content);
  const ruleContents = Object.values(props.rule_status.content);

  const items = [];
  if (ruleContents.length > 1) {
    ruleContents.forEach((versionContent, i) => {
      items.push({
        key: i,
        label: `Version ${ruleVersions[i] === 0 ? '< 39' : ruleVersions[i]}`,
        children: <SigContent dangerouslySetInnerHTML={{ __html: versionContent }} key={versionContent} />,
      });
    });
  }

  return (
    <Modal
      title={<div>Transformed rule content in {props.rule_status.name}</div>}
      visible={props.display}
      onCancel={props.close}
      footer={null}
      aria-labelledby="contained-modal-title-lg"
    >
      {ruleContents.length === 1 && <SigContent dangerouslySetInnerHTML={{ __html: ruleContents[0] }} key={ruleContents[0]} />}
      {ruleContents.length > 1 && <Tabs defaultActiveKey="1" items={items} />}
    </Modal>
  );
};

RuleContentModal.propTypes = {
  rule_status: PropTypes.any,
  display: PropTypes.any,
  close: PropTypes.any,
};
export default RuleContentModal;
