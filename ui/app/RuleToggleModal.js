/* eslint-disable react/no-access-state-in-setstate */
import React from 'react';

import { Button, Checkbox, Form, Input, InputNumber, Modal, Select } from 'antd';
import axios from 'axios';
import { cloneDeep } from 'lodash';
import PropTypes from 'prop-types';
import { withRouter } from 'react-router-dom';
import styled from 'styled-components';

import * as config from 'config/Api';
import { buildFilterParams } from 'ui/buildFilterParams';
import { buildQFilter } from 'ui/buildQFilter';
import { supportedActions, setDefaultOptions } from 'ui/supportedActions';

const RulesetMsg = styled.div`
  color: #ff4d4f;
  height: 22px;
  opacity: ${p => (p.errors && p.errors.rulesets && p.rulesets.length === 0 ? 1 : 0)};
  visibility: ${p => (p.errors && p.errors.rulesets && p.rulesets.length === 0 ? 'visible' : 'hidden')};
  transition: all 0.3s;
`;

const { Option } = Select;

axios.defaults.xsrfCookieName = 'csrftoken';
axios.defaults.xsrfHeaderName = 'X-CSRFToken';

class RuleToggleModal extends React.Component {
  constructor(props) {
    super(props);
    this.state = {
      rulesets: [],
      supported_filters: [],
      comment: '',
      options: {},
      errors: undefined,
      submitting: false,
    };
    this.submit = this.submit.bind(this);
    this.close = this.close.bind(this);
    this.handleChange = this.handleChange.bind(this);
    this.handleCommentChange = this.handleCommentChange.bind(this);
    this.handleFieldChange = this.handleFieldChange.bind(this);
    this.handleOptionsChange = this.handleOptionsChange.bind(this);
    this.updateActionDialog = this.updateActionDialog.bind(this);
    this.setDefaultOptions = setDefaultOptions.bind(this);
    this.onFieldKeyPress = this.onFieldKeyPress.bind(this);
    this.toggleFilter = this.toggleFilter.bind(this);
  }

  componentDidMount() {
    this.updateActionDialog();
    this.setDefaultOptions();
  }

  componentDidUpdate(prevProps) {
    if (prevProps.filters !== this.props.filters || prevProps.action !== this.props.action || prevProps.show !== this.props.show) {
      this.updateActionDialog();
      this.setDefaultOptions();
    }
  }

  onFieldKeyPress = keyEvent => {
    if (keyEvent.key === 'Enter') {
      keyEvent.stopPropagation();
      keyEvent.preventDefault();
    }
  };

  updateActionDialog() {
    if (!this.props.show) return;
    if (['enable', 'disable'].indexOf(this.props.action) !== -1) {
      this.setState({ supported_filters: [], noaction: false, errors: undefined });
      return;
    }
    if (this.props.filters && this.props.filters.length > 0) {
      const wantedFilters = Array.from(this.props.filters, x => x.id);
      const reqData = { fields: wantedFilters, action: this.props.action };
      axios
        .post(`${config.API_URL + config.PROCESSING_PATH}test/`, reqData)
        .then(res => {
          const suppFilters = [];
          let notfound = true;
          for (let i = 0; i < this.props.filters.length; i += 1) {
            if (this.props.action === 'threshold' && this.props.filters[i].negated) {
              // Negated filters on threshold are not supported
              // eslint-disable-next-line no-continue
              continue;
            }

            if (res.data.fields.indexOf(this.props.filters[i].id) !== -1) {
              const filter = cloneDeep(this.props.filters[i].toJSON());

              if (this.props.filters[i].negated === false) {
                filter.operator = 'equal';
              } else if (res.data.operators.indexOf('different') !== -1) {
                filter.operator = 'different';
              }

              filter.isChecked = true;
              filter.key = filter.id;
              filter.id = `filter${i}`;
              suppFilters.push(filter);
              notfound = false;
            }
          }

          let errors;
          if (notfound) {
            if (!res.data.supported_fields) {
              errors = { filters: ['No filters available'] };
            } else {
              const negatedError = this.props.action === 'threshold' ? ' (negated filter are not supported)' : '';
              errors = { filters: [`Supported filters are ${res.data.supported_fields}${negatedError}`] };
            }
          }
          this.setState({ supported_filters: suppFilters, noaction: notfound, errors });
        })
        .catch(error => {
          if (error.response.status === 403) {
            this.setState({ errors: { permission: ['Insufficient permissions'] }, noaction: true });
          }
        });
    } else {
      this.setState({ errors: { filters: ['No filters available'] }, noaction: true });
    }
  }

  close() {
    this.setState({ errors: undefined, rulesets: [] });
    this.props.close();
  }

  submit() {
    this.setState({ submitting: true });
    if (['enable', 'disable'].indexOf(this.props.action) !== -1) {
      if (this.state.rulesets.length === 0) {
        this.setState({ errors: { rulesets: ['Please select a rule set'] } });
      }
      this.state.rulesets.map(ruleset => {
        const data = { ruleset };
        if (this.state.comment.length > 0) {
          data.comment = this.state.comment;
        }
        let url = config.API_URL + config.RULE_PATH + this.props.config.rule.sid;
        if (this.props.action === 'enable') {
          url = `${url}/enable/`;
        } else {
          url = `${url}/disable/`;
        }
        axios
          .post(url, data)
          .then(() => {
            // Fixme notification or something
            if (this.props.refresh_callback) {
              this.props.refresh_callback();
            }
            this.close();
          })
          .catch(error => {
            this.setState({ errors: error.response.data });
          });
        return true;
      });
      this.setState({ submitting: false });
    } else if (supportedActions.concat(['suppress']).indexOf(this.props.action) !== -1) {
      // {"filter_defs": [{"key": "src_ip", "value": "192.168.0.1", "operator": "equal"}], "action": "suppress", "rulesets": [1]}

      const filters = [];
      for (let j = 0; j < this.state.supported_filters.length; j += 1) {
        if (this.state.supported_filters[j].isChecked) {
          filters.push({
            ...this.state.supported_filters[j],
            full_string: this.state.supported_filters[j].fullString,
          });
        }
      }
      const data = {
        filter_defs: filters,
        action: this.props.action,
        rulesets: this.state.rulesets,
      };
      // Attach comment post param only if there is value otherwise gitlab fails
      if (this.state.comment && this.state.comment.length > 0) {
        data.comment = this.state.comment;
      }
      if (supportedActions.indexOf(this.props.action) !== -1) {
        data.options = this.state.options;
      }

      const url = `${config.API_URL}${config.PROCESSING_PATH}?${buildFilterParams(this.props.filterParams)}${buildQFilter(
        this.props.filters,
        this.props.systemSettings,
      )}`;
      axios
        .post(url, data)
        .then(() => {
          this.setState({ submitting: false });
          this.close();
          this.props.history.push('/stamus/hunting/policies');
        })
        .catch(error => {
          this.setState({ errors: error.response.data, submitting: false });
        });
    }
    this.props.reload();
  }

  handleChange(event) {
    const { target } = event;
    const value = target.type === 'checkbox' ? target.checked : target.value;
    const { name } = target;
    const selList = this.state.rulesets;
    if (value === false) {
      // pop element
      const index = selList.indexOf(name);
      if (index >= 0) {
        selList.splice(index, 1);
        this.setState({ rulesets: selList });
      }
    } else if (selList.indexOf(name) < 0) {
      selList.push(name);
      this.setState({ rulesets: selList });
    }
  }

  handleCommentChange(event) {
    this.setState({ comment: event.target.value });
  }

  handleFieldChange(event, i) {
    const sfilters = Object.assign([], this.state.supported_filters);
    sfilters[i].value = event.target.value;
    this.setState({ supported_filters: sfilters });
  }

  handleOptionsChange(id, value) {
    const options = Object.assign({}, this.state.options);
    options[id] = value;
    this.setState({ options });
  }

  toggleFilter(i) {
    const sfilters = Object.assign([], this.state.supported_filters);
    sfilters[i].isChecked = !sfilters[i].isChecked;
    this.setState({ supported_filters: sfilters });
  }

  render() {
    let title = null;
    const middleDot = '•'; /* ignore_utf8_check 8226 */

    if (this.props.action === 'threat') {
      title = 'Define custom Declaration(s) of Compromise';
    } else if (this.props.config.rule) {
      const action = this.props.action === 'enable' ? 'Enable' : 'Disable';
      title = `${action} rule ${this.props.config.rule.sid}`;
    } else {
      title = `Add a ${this.props.action} action`;
    }
    return (
      <Modal
        visible={this.props.show}
        title={title}
        onCancel={this.close}
        footer={
          <React.Fragment>
            <Button className="btn-cancel" onClick={this.close} data-test="policy-actions-cancel">
              Cancel
            </Button>
            {!this.state.noaction && (
              <Button type="primary" onClick={this.submit} disabled={this.state.submitting} data-test="policy-actions-submit">
                Submit
              </Button>
            )}
          </React.Fragment>
        }
      >
        {this.props.action === 'threat' && (
          <div style={{ marginBottom: '30px' }}> These Declaration(s) of Compromise (DoC) will appear in the Custom Threats family</div>
        )}
        {!this.state.noaction && (
          <Form>
            {this.state.supported_filters &&
              this.state.supported_filters.map((item, i) => (
                <Form.Item key={item.id} style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', alignItems: 'center' }}>
                    <Checkbox defaultChecked onChange={() => this.toggleFilter(i)}>
                      <strong>
                        {item.negated && 'Not '}
                        {item.key}
                      </strong>
                    </Checkbox>
                    <Input
                      type={item.id}
                      disabled={!item.isChecked}
                      defaultValue={item.value}
                      onChange={e => this.handleFieldChange(e, i)}
                      onKeyPress={e => this.onFieldKeyPress(e)}
                    />
                  </div>
                </Form.Item>
              ))}
            {this.props.action === 'threshold' && (
              <React.Fragment>
                <Form.Item key="count" style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', alignItems: 'center' }}>
                    <strong>Count</strong>
                    <InputNumber defaultValue={1} onChange={value => this.handleOptionsChange('count', value)} style={{ width: '100%' }} />
                  </div>
                </Form.Item>
                <Form.Item key="seconds" style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', alignItems: 'center' }}>
                    <strong>Seconds</strong>
                    <InputNumber defaultValue={60} onChange={v => this.handleOptionsChange('seconds', v)} style={{ width: '100%' }} />
                  </div>
                </Form.Item>
                <Form.Item key="track" style={{ marginBottom: '10px' }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', alignItems: 'center' }}>
                    <strong>Track by</strong>
                    <Select placeholder="By Source" onChange={v => this.handleOptionsChange('track', v)} allowClear>
                      <Option value="by_src">By Source</Option>
                      <Option value="by_dst">By Destination</Option>
                    </Select>
                  </div>
                </Form.Item>
              </React.Fragment>
            )}
            {this.props.children && this.props.children(this)}

            <Form.Item style={{ marginBottom: '0' }}>
              <React.Fragment>
                <strong>Ruleset{this.props.rulesets.length > 1 && 's'}:</strong>
                <div style={{ display: 'grid', gridTemplateColumns: '2fr max-content', alignItems: 'center', justifyContent: 'space-around' }}>
                  {this.props.rulesets &&
                    this.props.rulesets.map(ruleset => (
                      <React.Fragment key={ruleset.pk}>
                        <label htmlFor={ruleset.pk}>{ruleset.name}</label>
                        <Checkbox
                          data-test={`${ruleset.name}`}
                          id={ruleset.pk}
                          name={ruleset.pk}
                          onChange={this.handleChange}
                          style={{ justifySelf: 'right' }}
                        />
                        {ruleset.warnings && (
                          <React.Fragment>
                            <div>{middleDot}</div>
                            <div>{ruleset.warnings}</div>
                          </React.Fragment>
                        )}{' '}
                        {ruleset[`warnings_${this.props.action}`] && (
                          <React.Fragment>
                            <div>{middleDot}</div>
                            <div>{ruleset[`warnings_${this.props.action}`]}</div>
                          </React.Fragment>
                        )}
                      </React.Fragment>
                    ))}
                </div>
                <RulesetMsg errors={this.state.errors} rulesets={this.state.rulesets}>
                  {this.state.rulesets.length === 0 && this.state.errors && this.state.errors.rulesets && this.state.errors.rulesets[0]}
                </RulesetMsg>
              </React.Fragment>
            </Form.Item>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', alignItems: 'center' }}>
              <strong>Optional comment</strong>
              <Input.TextArea value={this.state.comment} onChange={this.handleCommentChange} data-test="custom-threat-creation-optional-comment" />
            </div>
          </Form>
        )}
        {this.state.noaction && <p>You need enough permissions and at least a filter supported by the ruleset backend to define an action</p>}
      </Modal>
    );
  }
}

RuleToggleModal.propTypes = {
  filters: PropTypes.any,
  action: PropTypes.any,
  rulesets: PropTypes.any,
  refresh_callback: PropTypes.any,
  show: PropTypes.any,
  config: PropTypes.any,
  close: PropTypes.func,
  children: PropTypes.any,
  systemSettings: PropTypes.any,
  filterParams: PropTypes.any,
  history: PropTypes.any,
  reload: PropTypes.func,
};

export default withRouter(RuleToggleModal);
