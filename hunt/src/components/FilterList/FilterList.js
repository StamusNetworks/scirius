import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { ControlLabel, Icon, Modal } from 'patternfly-react';
import { Button, Checkbox, Col, Form, FormControl, FormGroup, HelpBlock, InputGroup, Row } from 'react-bootstrap';
import InputGroupAddon from 'react-bootstrap/es/InputGroupAddon';
import FilterItem from 'hunt_common/components/FilterItem/index';
import isNumeric from '../../helpers/isNumeric';
import './style.css';
import { editFilter, removeFilter } from '../../containers/App/stores/global';

class FilterList extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            editForm: false,
            filterIdx: '',
            filterId: '',
            newFilterValue: '',
            newFilterNegated: false,
            wildcardMode: false,
        }
    }

    componentDidUpdate(prevProps, prevState) {
        if (this.state.editForm === true && !prevState.editForm) {
            setTimeout(() => {
                document.querySelector('#input-value-filter').select();
            }, 100);
        }
    }

    editHandler = (filterIdx, filterId, filterValue, filterNegated, wildcardMode) => {
        wildcardMode = (filterId === 'host_id.ip') ? false : wildcardMode;
        this.setState({
            editForm: true,
            filterIdx,
            filterId,
            newFilterValue: filterValue,
            newFilterNegated: filterNegated,
            wildcardMode,
        })
    }

    closeHandler = () => {
        this.setState({
            editForm: false
        });
    }

    saveHandler = () => {
        this.props.editFilter(
            this.props.filterType,
            this.state.filterIdx,
            {
                label: `${this.state.filterId}: ${this.state.newFilterValue}`,
                value: this.state.newFilterValue,
                negated: this.state.newFilterNegated,
                fullString: !this.state.wildcardMode,
            }
        );
        this.closeHandler();
    }

    negateHandler = (e) => {
        this.setState({
            newFilterNegated: e.target.checked
        })
    }

    wildcardHandler = (e) => {
        this.setState({
            wildcardMode: e.target.checked
        })
    }

    keyListener = (e) => {
        const newFilterValue = this.state.newFilterValue.toString();
        // Enter key handler
        if (e.keyCode === 13) {
            e.preventDefault();
            if (newFilterValue.length && !newFilterValue.match(/ /g)) {
                this.saveHandler();
            }
        }
    }

    render() {
        const newFilterValue = this.state.newFilterValue.toString();
        const valid = (!newFilterValue.toString().length || (this.state.wildcardMode && newFilterValue.match(/[\s]+/g)) ? 'error' : 'success');
        let helperText = '';
        if (['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max'].includes(this.state.filterId)) {
            helperText = 'Case insensitive substring match.';
        } else if (this.state.wildcardMode) {
            helperText = <React.Fragment>Wildcard characters (<i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>*</i> and <i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>?</i>) can match on word boundaries.<br />No spaces allowed.</React.Fragment>;
        } else {
            helperText = 'Exact match'
        }
        helperText = (!['hits_min', 'hits_max'].includes(this.state.filterId)) ? helperText : '';

        return <React.Fragment>
            {/* eslint-disable react/no-array-index-key */}
            <ul className="list-inline">{this.props.filters.map((filter, idx) => <FilterItem key={idx}
                addFilter={this.props.addFilter}
                onRemove={() => this.props.removeFilter(this.props.filterType, idx)}
                onEdit={() => this.editHandler(idx, filter.id, filter.value, filter.negated, !filter.fullString)}
                editFilter={this.props.editFilter}
                filters={this.props.filters}
                filterType={this.props.filterType}
                idx={idx}
                {...filter}
            />)}</ul>
            <Modal show={this.state.editForm} onHide={() => this.setState({ editForm: false })} className={'modal-hunt-filter'} backdrop keyboard>
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
                    <Form>
                        <FormGroup controlId="name">
                            <Col componentClass={ControlLabel} sm={2}>
                                <ControlLabel>Filter</ControlLabel>
                            </Col>
                            <Col sm={10}>
                                <InputGroup>
                                    <InputGroupAddon>{this.state.filterId}</InputGroupAddon>
                                    <FormGroup validationState={valid} className={'form-group-no-margins'}>
                                        <FormControl
                                            id={'input-value-filter'}
                                            type="text"
                                            value={newFilterValue}
                                            onKeyDown={this.keyListener}
                                            onChange={(e) => this.setState({
                                                newFilterValue: (isNumeric(e.target.value)) ? parseInt(e.target.value, 10) : e.target.value
                                            })}
                                            className={'has-error'}
                                        />
                                    </FormGroup>
                                </InputGroup>
                                <HelpBlock>{helperText}</HelpBlock>
                            </Col>
                        </FormGroup>
                        <Row>
                            <FormGroup controlId="checkbox">
                                <Col componentClass={ControlLabel} sm={3}>
                                    <ControlLabel>Wildcard view</ControlLabel>
                                </Col>
                                <Col sm={9}>
                                    <Checkbox onChange={this.wildcardHandler} onKeyDown={this.keyListener} checked={this.state.wildcardMode} disabled={(['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max', 'src_ip', 'dest_ip', 'alert.source.ip', 'alert.target.ip', 'host_id.ip', 'ip'].includes(this.state.filterId))} />
                                </Col>
                            </FormGroup>
                        </Row>
                        {!['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max'].includes(this.state.filterId) && <Row>
                            <FormGroup controlId="checkbox">
                                <Col componentClass={ControlLabel} sm={3}>
                                    <ControlLabel>Negated</ControlLabel>
                                </Col>
                                <Col sm={9}>
                                    <Checkbox onChange={this.negateHandler} onKeyDown={this.keyListener} checked={this.state.newFilterNegated} disabled={(['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max'].includes(this.state.filterId))} />
                                </Col>
                            </FormGroup>
                        </Row>}
                    </Form>
                </Modal.Body>
                <Modal.Footer>
                    <Button onClick={this.closeHandler}>Cancel</Button>
                    <Button
                        bsStyle="primary"
                        disabled={(valid === 'error')}
                        onClick={this.saveHandler}
                    >Save</Button>
                </Modal.Footer>
            </Modal>
        </React.Fragment>
    }
}

FilterList.propTypes = {
    filters: PropTypes.array,
    editFilter: PropTypes.func,
    removeFilter: PropTypes.func,
    filterType: PropTypes.string,
}

const mapDispatchToProps = {
    editFilter,
    removeFilter,
};

export default connect(null, mapDispatchToProps)(FilterList);
