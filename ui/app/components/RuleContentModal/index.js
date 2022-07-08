import React from 'react';
import PropTypes from 'prop-types';
import { Modal } from 'antd';

const RuleContentModal = props => (
  <Modal
    title={<div>Transformed rule content in {props.rule_status.name}</div>}
    visible={props.display}
    onCancel={props.close}
    footer={null}
    aria-labelledby="contained-modal-title-lg"
  >
    {/* eslint-disable-next-line react/no-danger */}
    <div className="SigContent" dangerouslySetInnerHTML={{ __html: props.rule_status.content }}></div>
  </Modal>
);

RuleContentModal.propTypes = {
  rule_status: PropTypes.any,
  display: PropTypes.any,
  close: PropTypes.any,
};
export default RuleContentModal;
