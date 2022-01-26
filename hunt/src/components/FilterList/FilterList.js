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

export const IP_FIELDS = [
  'src_ip',
  'dest_ip',
  'alert.source.ip',
  'alert.target.ip',
  'host_id.ip',
  'ip',
  'dns.rdata',
  'dns.answers.rdata',
  'dns.grouped.A',
  'dns.grouped.AAAA',
  'tunnel.src_ip',
  'tunnel.dest_ip',
];

export const INTERGER_FIELDS_ENDS_WITH = ['.min', '.max', '_min', '_max', '.port', '_port', '.length'];
export const INTERGER_FIELDS_EXACT = [
  'alert.signature_id',
  'alert.rev',
  'alert.severity',
  'http.status',
  'vlan',
  'flow_id',
  'flow.bytes_toclient',
  'flow.bytes_toserver',
  'flow.pkts_toclient',
  'flow.pkts_toserver',
  'geoip.provider.autonomous_system_number',
  'port',
];

class FilterList extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      editForm: false,
      filter: { id: '' },
      newFilterValue: '',
      newFilterNegated: false,
      wildcardMode: false,
    };
  }

  componentDidUpdate(prevProps, prevState) {
    if (this.state.editForm === true && !prevState.editForm) {
      setTimeout(() => {
        document.querySelector('#input-value-filter').select();
      }, 100);
    }
  }

  editHandler = (filter, filterValue, filterNegated, wildcardMode) => {
    const wildcardEnabled = filter.id === 'host_id.ip' ? false : wildcardMode;
    this.setState({
      editForm: true,
      filter,
      newFilterValue: filterValue,
      newFilterNegated: filterNegated,
      wildcardMode: wildcardEnabled,
    });
  };

  closeHandler = () => {
    this.setState({
      editForm: false,
    });
  };

  saveHandler = () => {
    const newFilterValue = isNumeric(this.state.newFilterValue) ? parseInt(this.state.newFilterValue, 10) : this.state.newFilterValue;
    this.props.editFilter(this.props.filterType, this.state.filter, {
      id: this.state.filter.id,
      label: `${this.state.filter.id}: ${this.state.newFilterValue}`,
      value: newFilterValue,
      negated: this.state.newFilterNegated,
      fullString: !this.state.wildcardMode,
    });
    this.closeHandler();
  };

  negateHandler = (e) => {
    this.setState({
      newFilterNegated: e.target.checked,
    });
  };

  changeHandler = (e, filterType) => {
    const value = filterType === 'host_id.roles.name' ? e.target.value : e.target.value.trim();
    this.setState({
      newFilterValue: value,
    });
  };

  wildcardHandler = (e) => {
    this.setState({
      wildcardMode: e.target.checked,
    });
  };

  keyListener = (e) => {
    const newFilterValue = this.state.newFilterValue.toString();
    // Enter key handler
    if (e.keyCode === 13) {
      e.preventDefault();
      if (newFilterValue.length && !newFilterValue.match(/ /g)) {
        this.saveHandler();
      }
    }
  };

  render() {
    const newFilterValue = this.state.newFilterValue.toString();
    const isInteger =
      INTERGER_FIELDS_ENDS_WITH.findIndex((item) => this.state.filter.id.endsWith(item)) !== -1 ||
      INTERGER_FIELDS_EXACT.includes(this.state.filter.id);
    const controlType = !isInteger ? 'text' : 'number';

    let enableWildcard = !['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max', 'es_filter'].includes(this.state.filter.id);
    enableWildcard = enableWildcard && !IP_FIELDS.includes(this.state.filter.id) && !isInteger;

    const valid =
      !newFilterValue.toString().length || (this.state.wildcardMode && enableWildcard && newFilterValue.match(/[\s]+/g)) ? 'error' : 'success';
    let helperText = '';
    if (['msg', 'not_in_msg', 'search', 'not_in_content'].includes(this.state.filter.id)) {
      helperText = 'Case insensitive substring match.';
    } else if (['hits_min', 'hits_max'].includes(this.state.filter.id)) {
      helperText = '';
    } else if (['es_filter'].includes(this.state.filter.id)) {
      helperText = 'Free ES filter with Lucene syntax';
    } else if (this.state.wildcardMode && enableWildcard) {
      helperText = (
        <React.Fragment>
          Wildcard characters (<i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>*</i> and{' '}
          <i style={{ padding: '0px 5px', background: '#e0e0e0', margin: '0 2px' }}>?</i>) can match on word boundaries.
          <br />
          No spaces allowed.
        </React.Fragment>
      );
    } else {
      helperText = 'Exact match';
    }

    return (
      <React.Fragment>
        {/* eslint-disable react/no-array-index-key */}
        <ul className="list-inline">
          {this.props.filters.map((filter, idx) => (
            <FilterItem
              key={idx}
              onRemove={() => this.props.removeFilter(this.props.filterType, filter)}
              onEdit={() => this.editHandler(filter, filter.value, filter.negated, !filter.fullString)}
              editFilter={this.props.editFilter}
              filters={this.props.filters}
              filterType={this.props.filterType}
              filter={filter}
            />
          ))}
        </ul>
        <Modal show={this.state.editForm} onHide={() => this.setState({ editForm: false })} className="modal-hunt-filter" backdrop keyboard>
          <Modal.Header>
            <button type="button" className="close" onClick={this.closeHandler} aria-hidden="true" aria-label="Close">
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
                    <InputGroupAddon>{this.state.filter.id}</InputGroupAddon>
                    <FormGroup validationState={valid} className="form-group-no-margins">
                      <FormControl
                        id="input-value-filter"
                        type={controlType}
                        value={newFilterValue}
                        onKeyDown={this.keyListener}
                        onChange={(e) => this.changeHandler(e, this.state.filter.id)}
                        className="has-error"
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
                    <Checkbox
                      onChange={this.wildcardHandler}
                      onKeyDown={this.keyListener}
                      checked={this.state.wildcardMode && enableWildcard}
                      disabled={!enableWildcard}
                    />
                  </Col>
                </FormGroup>
              </Row>
              {!['msg', 'not_in_msg', 'search', 'not_in_content', 'hits_min', 'hits_max'].includes(this.state.filter.id) && (
                <Row>
                  <FormGroup controlId="checkbox">
                    <Col componentClass={ControlLabel} sm={3}>
                      <ControlLabel>Negated</ControlLabel>
                    </Col>
                    <Col sm={9}>
                      <Checkbox onChange={this.negateHandler} onKeyDown={this.keyListener} checked={this.state.newFilterNegated} />
                    </Col>
                  </FormGroup>
                </Row>
              )}
            </Form>
          </Modal.Body>
          <Modal.Footer>
            <Button onClick={this.closeHandler}>Cancel</Button>
            <Button bsStyle="primary" disabled={valid === 'error'} onClick={this.saveHandler}>
              Save
            </Button>
          </Modal.Footer>
        </Modal>
      </React.Fragment>
    );
  }
}

FilterList.propTypes = {
  filters: PropTypes.array,
  editFilter: PropTypes.func,
  removeFilter: PropTypes.func,
  filterType: PropTypes.string,
};

const mapDispatchToProps = {
  editFilter,
  removeFilter,
};

export default connect(null, mapDispatchToProps)(FilterList);
