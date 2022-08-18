import React from 'react';
import PropTypes from 'prop-types';
import { connect } from 'react-redux';
import { Button, Checkbox, Col, Form, Input, InputNumber, Modal, Row } from 'antd';
import FilterItem from 'ui/components/FilterItem/index';
import { editFilter, removeFilter } from 'ui/containers/HuntApp/stores/global';
import styled from 'styled-components';
import isNumeric from '../../helpers/isNumeric';

const ListInline = styled.span`
  list-style: none;
  display: inline-block;
  margin: 0;
  margin-block-start: 0;
  margin-block-end: 0;
  padding-inline-start: 0;

  & li {
    box-sizing: border-box;
    color: rgb(65, 64, 66);
    display: inline-block;
    font-family: 'Open Sans', Helvetica, Arial, sans-serif;
    font-size: 12px;
    height: 23.5px;
    line-height: 40px;
    list-style: none outside none;
    padding-left: 5px;
    padding-right: 5px;
    text-align: left;
  }
`;

const ModalHuntFilter = styled(Modal)`
  & .modal-body {
    padding-bottom: 0;
  }
  & .modal-footer {
    margin-top: 0;
  }
`;

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

  saveHandler = () => {
    const newFilterValue = isNumeric(this.state.newFilterValue) ? parseInt(this.state.newFilterValue, 10) : this.state.newFilterValue;
    this.props.editFilter(this.props.filterType, this.state.filter, {
      id: this.state.filter.id,
      label: `${this.state.filter.id}: ${this.state.newFilterValue}`,
      value: newFilterValue,
      negated: this.state.newFilterNegated,
      fullString: !this.state.wildcardMode,
    });
    this.setState({ editForm: false });
  };

  negateHandler = e => {
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

  wildcardHandler = e => {
    this.setState({
      wildcardMode: e.target.checked,
    });
  };

  keyListener = e => {
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
      INTERGER_FIELDS_ENDS_WITH.findIndex(item => this.state.filter.id.endsWith(item)) !== -1 || INTERGER_FIELDS_EXACT.includes(this.state.filter.id);
    const controlType = !isInteger ? 'text' : 'number';

    let enableWildcard = !['msg', 'not_in_msg', 'content', 'not_in_content', 'hits_min', 'hits_max', 'es_filter'].includes(this.state.filter.id);
    enableWildcard = enableWildcard && !IP_FIELDS.includes(this.state.filter.id) && !isInteger;

    const valid =
      !newFilterValue.toString().length || (this.state.wildcardMode && enableWildcard && newFilterValue.match(/[\s]+/g)) ? 'error' : 'success';
    let helperText = '';
    if (['msg', 'not_in_msg', 'content', 'not_in_content'].includes(this.state.filter.id)) {
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
        <ListInline>
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
        </ListInline>
        <ModalHuntFilter
          title="Edit filter"
          visible={this.state.editForm}
          onCancel={() => this.setState({ editForm: false })}
          className="modal-hunt-filter"
          footer={
            <React.Fragment>
              <Button onClick={() => this.setState({ editForm: false })}>Cancel</Button>
              <Button type="primary" disabled={valid === 'error'} onClick={this.saveHandler}>
                Save
              </Button>
            </React.Fragment>
          }
        >
          <Form>
            <Form.Item name="name">
              <Row>
                <Col span={4}>
                  <label>Filter</label>
                </Col>
                <Col span={20}>
                  <Form.Item validateStatus={valid}>
                    <span>{this.state.filter.id}</span>
                    {controlType === 'text' ? (
                      <Input
                        id="input-value-filter"
                        value={newFilterValue}
                        onKeyDown={this.keyListener}
                        onChange={e => this.changeHandler(e, this.state.filter.id)}
                        style={{ width: '100%' }}
                      />
                    ) : (
                      <InputNumber
                        id="input-value-filter"
                        value={newFilterValue}
                        onKeyDown={this.keyListener}
                        onChange={e => this.setState({ newFilterValue: e.target.value.trim() })}
                        style={{ width: '100%' }}
                      />
                    )}
                  </Form.Item>
                  <span style={{ color: '#b4b3b5' }}>{helperText}</span>
                </Col>
              </Row>
            </Form.Item>
            <Form.Item name="checkbox-wildcard_view">
              <Row>
                <Col span={6}>
                  <label>Wildcard view</label>
                </Col>
                <Col span={18}>
                  <Checkbox
                    onChange={this.wildcardHandler}
                    onKeyDown={this.keyListener}
                    checked={this.state.wildcardMode && enableWildcard}
                    disabled={!enableWildcard}
                  />
                </Col>
              </Row>
            </Form.Item>

            {!['msg', 'not_in_msg', 'content', 'not_in_content', 'hits_min', 'hits_max'].includes(this.state.filter.id) && (
              <Form.Item name="checkbox-negated">
                <Row>
                  <Col span={6}>
                    <label>Negated</label>
                  </Col>
                  <Col span={18}>
                    <Checkbox onChange={this.negateHandler} onKeyDown={this.keyListener} checked={this.state.newFilterNegated} />
                  </Col>
                </Row>
              </Form.Item>
            )}
          </Form>
        </ModalHuntFilter>
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
