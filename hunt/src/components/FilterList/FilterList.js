import React from 'react';
import PropTypes from 'prop-types';
import { ControlLabel, Icon, Modal } from 'patternfly-react';
import { Button, Checkbox, Col, Form, FormControl, FormGroup, HelpBlock, InputGroup } from 'react-bootstrap';
import InputGroupAddon from 'react-bootstrap/es/InputGroupAddon';
import FilterItem from '../FilterItem/index';
import isNumeric from '../../helpers/isNumeric';
import './style.css';

export default class FilterList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            editForm: false,
            filterIdx: '',
            filterId: '',
            newFilterValue: '',
            newFilterNegated: false,
        }
    }

    editHandler = (filterIdx, filterId, filterValue, filterNegated) => {
        this.setState({
            editForm: true,
            filterIdx,
            filterId,
            newFilterValue: filterValue,
            newFilterNegated: filterNegated,
        })
    }

    closeHandler = () => {
        this.setState({
            editForm: false
        });
    }

    saveHandler = () => {
        const index = this.state.filterIdx;
        if (index > -1) {
            /* eslint-disable-next-line */
            const activeFilters = this.props.filters.map((v, i) => {
                return (i === index) ? {
                    ...v,
                    label: `${this.state.filterId}: ${this.state.newFilterValue}`,
                    value: this.state.newFilterValue,
                    negated: this.state.newFilterNegated,
                    fullString: false,
                } : v;
            });
            this.props.updateFilter(activeFilters);
        }
        this.closeHandler();
    }

    negateHandler = (e) => {
        this.setState({
            newFilterNegated: e.target.checked
        })
    }

    render() {
        const newFilterValue = this.state.newFilterValue.toString();
        return <React.Fragment>
            {/* eslint-disable react/no-array-index-key */}
            <ul className="list-inline">{this.props.filters.map((filter, idx) => <FilterItem key={idx} onRemove={() => this.props.onRemove(idx)} onEdit={() => this.editHandler(idx, filter.id, filter.value, filter.negated)} {...filter} />)}</ul>
            <Modal show={this.state.editForm} className={'modal-hunt-filter'} backdrop keyboard>
                <Modal.Header>
                    <button
                        className="close"
                        onClick={this.closeHandler}
                        aria-hidden="true"
                        aria-label="Close"
                    >
                        <Icon type="pf" name="close" />
                    </button>
                    <Modal.Title>Edit filter</Modal.Title>
                </Modal.Header>
                <Modal.Body>
                    <Form horizontal>
                        <FormGroup controlId="name">
                            <Col componentClass={ControlLabel} sm={2}>
                                <ControlLabel>Filter</ControlLabel>
                            </Col>
                            <Col sm={10}>
                                <InputGroup>
                                    <InputGroupAddon>{this.state.filterId}</InputGroupAddon>
                                    <FormGroup validationState={(newFilterValue.length && newFilterValue.match(/ /g) ? 'error' : 'success')} className={'form-group-no-margins'}>
                                        <FormControl
                                            type="text"
                                            value={newFilterValue}
                                            onKeyDown={(e) => {
                                                if (e.keyCode === 13) {
                                                    e.preventDefault();
                                                    this.saveHandler();
                                                }
                                            }}
                                            onChange={(e) => this.setState({
                                                newFilterValue: (isNumeric(e.target.value)) ? parseInt(e.target.value, 10) : e.target.value
                                            })}
                                            className={'has-error'}
                                        />
                                    </FormGroup>
                                </InputGroup>
                                <HelpBlock>Enter your filter value</HelpBlock>
                            </Col>
                        </FormGroup>
                        <FormGroup controlId="checkbox">
                            <Col componentClass={ControlLabel} sm={2}>
                                <ControlLabel>Negated</ControlLabel>
                            </Col>
                            <Col sm={10}>
                                <Checkbox onChange={this.negateHandler} checked={this.state.newFilterNegated}>Filter is negated</Checkbox>
                                <HelpBlock>Check it if you want to negate the filter</HelpBlock>
                            </Col>
                        </FormGroup>

                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.closeHandler}>Cancel</Button>
                    <Button bsStyle="primary" disabled={!!(newFilterValue.toString().length && newFilterValue.toString().match(/ /g))} onClick={this.saveHandler}>Save</Button>
                </Modal.Footer>
            </Modal>
        </React.Fragment>
    }
}

FilterList.propTypes = {
    filters: PropTypes.array,
    onRemove: PropTypes.func,
    updateFilter: PropTypes.func,
}
