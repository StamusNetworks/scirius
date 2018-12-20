/* eslint-disable react/no-danger */
import React from 'react';
import PropTypes from 'prop-types';
import { Modal, Icon } from 'patternfly-react';

const RuleContentModal = (props) => (
    <Modal
        show={props.display}
        onHide={props.close}
        bsSize="large"
        aria-labelledby="contained-modal-title-lg"
    >
        <Modal.Header>
            <button
                className="close"
                onClick={props.close}
                aria-hidden="true"
                aria-label="Close"
            >
                <Icon type="pf" name="close" />
            </button>
            <Modal.Title>Transformed rule content in {props.rule_status.name}</Modal.Title>
        </Modal.Header>
        <Modal.Body>
            <div className="SigContent" dangerouslySetInnerHTML={{ __html: props.rule_status.content }}></div>
        </Modal.Body>
    </Modal>
);

RuleContentModal.propTypes = {
    rule_status: PropTypes.any,
    display: PropTypes.any,
    close: PropTypes.any,
};
export default RuleContentModal;
