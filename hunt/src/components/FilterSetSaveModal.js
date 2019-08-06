import React from 'react';
import PropTypes from 'prop-types';
import { Checkbox, Col, Form, FormControl, FormGroup, Button, Icon, Modal } from 'patternfly-react';
import VerticalNavItems from 'hunt_common/components/VerticalNavItems';
import HuntRestError from './HuntRestError';

const FilterSetSaveModal = (props) => (
    <Modal show={props.showModal} onHide={props.close}>
        <div onClick={
            // Stopping event propagation is required since the modal is the children of a list item that
            // will also react to clicks
            (e) => { e.stopPropagation() }
        }
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
                <Modal.Title>{props.title}</Modal.Title>
            </Modal.Header>
            <Modal.Body>
                <HuntRestError errors={props.errors} />
                <Form horizontal>
                    <FormGroup key={'name'} controlId={'name'}>
                        <Col sm={4}>
                            <strong>Name</strong>
                        </Col>
                        <Col sm={8}>
                            <FormControl defaultValue={''} onChange={props.handleFieldChange} />
                        </Col>
                    </FormGroup>
                    <FormGroup key={'page'} controlId={'page'}>
                        <Col sm={4}>
                            <strong>Page</strong>
                        </Col>
                        <Col sm={8}>
                            {!props.page && <FormControl componentClass="select" placeholder="relevant" onChange={props.handleComboChange}>
                                {VerticalNavItems.filter((item) => (
                                    item.title !== 'Actions')).map((item) => (
                                        <option key={item.title} value={item.def}>{item.title}</option> // eslint-disable-line indent
                                ))}
                            </FormControl>}
                            {props.page && <FormControl disabled defaultValue={props.page} />}
                        </Col>
                    </FormGroup>
                    {!props.noRights && <FormGroup>
                        <Col sm={2}>
                            <Checkbox
                                defaultChecked={false}
                                onChange={(e) => {
                                    props.setSharedFilter(e);
                                }}
                            ><strong>Shared</strong>
                            </Checkbox>
                        </Col>
                        <Col>
                            <span className="pficon-help"
                                data-toggle="tooltip"
                                title="Enable: Create Filter Set with All Users&#10;Disable: Create Filter Set only for you"
                            />
                        </Col>
                    </FormGroup>}
                    <FormGroup>
                        <Col sm={4}>
                            <strong>Description:</strong>
                        </Col>
                        <Col sm={8}>
                            <textarea cols="49" rows="3" onChange={props.handleDescriptionChange} />
                        </Col>
                    </FormGroup>
                </Form>
            </Modal.Body>

            <Modal.Footer>
                <Button
                    bsStyle="default"
                    className="btn-cancel"
                    onClick={props.close}
                >
                    Cancel
                </Button>
                <Button bsStyle="primary" onClick={props.submit}>
                    Save
                </Button>

            </Modal.Footer>
        </div>
    </Modal>
);

FilterSetSaveModal.propTypes = {
    title: PropTypes.any,
    showModal: PropTypes.any,
    close: PropTypes.any,
    errors: PropTypes.any,
    handleDescriptionChange: PropTypes.any,
    handleComboChange: PropTypes.any,
    handleFieldChange: PropTypes.any,
    setSharedFilter: PropTypes.any,
    submit: PropTypes.any,
    page: PropTypes.any,
    noRights: PropTypes.bool.isRequired
};

export default FilterSetSaveModal;
