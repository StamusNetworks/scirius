import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import { Modal, Button, Checkbox, Col, Form, FormControl, FormGroup, Icon } from 'patternfly-react';
import * as config from 'hunt_common/config/Api';
import HuntRestError from './components/HuntRestError';

export default class RuleToggleModal extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selected: [],
            supported_filters: [],
            comment: '',
            options: {},
            errors: undefined
        };
        this.submit = this.submit.bind(this);
        this.close = this.close.bind(this);
        this.handleChange = this.handleChange.bind(this);
        this.handleCommentChange = this.handleCommentChange.bind(this);
        this.handleFieldChange = this.handleFieldChange.bind(this);
        this.handleOptionsChange = this.handleOptionsChange.bind(this);
        this.updateActionDialog = this.updateActionDialog.bind(this);
        this.setDefaultOptions = this.setDefaultOptions.bind(this);
        this.onFieldKeyPress = this.onFieldKeyPress.bind(this);
        this.toggleFilter = this.toggleFilter.bind(this);
    }


    componentDidMount() {
        this.updateActionDialog();
        this.setDefaultOptions();
    }

    componentDidUpdate(prevProps) {
        if ((prevProps.filters !== this.props.filters) || (prevProps.action !== this.props.action)) {
            this.updateActionDialog();
            this.setDefaultOptions();
        }
    }

    onFieldKeyPress = (keyEvent) => {
        if (keyEvent.key === 'Enter') {
            keyEvent.stopPropagation();
            keyEvent.preventDefault();
        }
    }

    setDefaultOptions() {
        let options = {};
        switch (this.props.action) {
            case 'threshold':
                options = {
                    type: 'both', count: 1, seconds: 60, track: 'by_src'
                };
                break;
            case 'tag':
            case 'tagkeep':
                options = { tag: 'relevant' };
                break;
            default:
                break;
        }
        this.setState({ options });
    }

    updateActionDialog() {
        if (['enable', 'disable'].indexOf(this.props.action) !== -1) {
            this.setState({ supported_filters: [], noaction: false, errors: undefined });
            return;
        }
        if (this.props.filters && this.props.filters.length > 0) {
            const wantedFilters = Array.from(this.props.filters, (x) => x.id);
            const reqData = { fields: wantedFilters, action: this.props.action };
            axios.post(`${config.API_URL + config.PROCESSING_PATH}test/`, reqData).then((res) => {
                const suppFilters = [];
                let notfound = true;
                for (let i = 0; i < this.props.filters.length; i += 1) {
                    if (res.data.fields.indexOf(this.props.filters[i].id) !== -1) {
                        const filter = JSON.parse(JSON.stringify(this.props.filters[i]))

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
                    errors = { filters: ['No filters available'] };
                }
                this.setState({ supported_filters: suppFilters, noaction: notfound, errors });
            }).catch((error) => {
                if (error.response.status === 403) {
                    this.setState({ errors: { permission: ['Insufficient permissions'] }, noaction: true });
                }
            });
        } else {
            this.setState({ errors: { filters: ['No filters available'] }, noaction: true });
        }
    }

    close() {
        this.setState({ errors: undefined });
        this.props.close();
    }

    submit() {
        if (['enable', 'disable'].indexOf(this.props.action) !== -1) {
            this.state.selected.map(
                (ruleset) => {
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
                    axios.post(url, data).then(
                        () => {
                            // Fixme notification or something
                            if (this.props.refresh_callback) {
                                this.props.refresh_callback();
                            }
                            this.close();
                        }
                    ).catch((error) => {
                        this.setState({ errors: error.response.data });
                    });
                    return true;
                }
            );
        } else if (['suppress', 'threshold', 'tag', 'tagkeep'].indexOf(this.props.action) !== -1) {
            // {"filter_defs": [{"key": "src_ip", "value": "192.168.0.1", "operator": "equal"}], "action": "suppress", "rulesets": [1]}

            const filters = [];
            for (let j = 0; j < this.state.supported_filters.length; j += 1) {
                if (this.state.supported_filters[j].isChecked) {
                    filters.push(this.state.supported_filters[j]);
                }
            }
            const data = {
                filter_defs: filters, action: this.props.action, rulesets: this.state.selected, comment: this.state.comment
            };
            if (['threshold', 'tag', 'tagkeep'].indexOf(this.props.action) !== -1) {
                data.options = this.state.options;
            }
            axios.post(config.API_URL + config.PROCESSING_PATH, data).then(
                () => {
                    this.close();
                }
            ).catch(
                (error) => {
                    this.setState({ errors: error.response.data });
                }
            );
        }
    }

    handleChange(event) {
        const { target } = event;
        const value = target.type === 'checkbox' ? target.checked : target.value;
        const { name } = target;
        const selList = this.state.selected;
        if (value === false) {
            // pop element
            const index = selList.indexOf(name);
            if (index >= 0) {
                selList.splice(index, 1);
                this.setState({ selected: selList });
            }
        } else if (selList.indexOf(name) < 0) {
            selList.push(name);
            this.setState({ selected: selList });
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

    handleOptionsChange(event) {
        const options = Object.assign({}, this.state.options);
        options[event.target.id] = event.target.value;
        this.setState({ options });
    }

    toggleFilter(i) {
        const sfilters = Object.assign([], this.state.supported_filters);
        sfilters[i].isChecked = !sfilters[i].isChecked;
        this.setState({ supported_filters: sfilters });
    }

    render() {
        return (
            <Modal show={this.props.show} onHide={this.close}>
                <Modal.Header>
                    <button
                        className="close"
                        onClick={this.close}
                        aria-hidden="true"
                        aria-label="Close"
                    >
                        <Icon type="pf" name="close" />
                    </button>
                    {this.props.config.rule && <Modal.Title>{this.props.action} Rule {this.props.config.rule.sid}</Modal.Title>}
                    {!this.props.config.rule && <Modal.Title>Add a {this.props.action} action</Modal.Title>}
                </Modal.Header>
                <Modal.Body>
                    <HuntRestError errors={this.state.errors} />
                    {!this.state.noaction && <Form horizontal>
                        {this.state.supported_filters && this.state.supported_filters.map((item, i) => (
                            <FormGroup key={item.id} controlId={item.id}>
                                <Col sm={4}>
                                    <Checkbox
                                        defaultChecked
                                        onChange={() => this.toggleFilter(i)}
                                    ><strong>{item.negated && 'Not '}{item.key}</strong>
                                    </Checkbox>
                                </Col>
                                <Col sm={8}>
                                    <FormControl type={item.id} disabled={!item.isChecked} defaultValue={item.value} onChange={(e) => this.handleFieldChange(e, i)} onKeyPress={(e) => this.onFieldKeyPress(e)} />
                                </Col>
                            </FormGroup>
                        ))}
                        {this.props.action === 'threshold' && <React.Fragment>
                            <FormGroup key="count" controlId="count" disabled={false}>
                                <Col sm={4}>
                                    <strong>Count</strong>
                                </Col>
                                <Col sm={8}>
                                    <FormControl type="integer" disabled={false} defaultValue={1} onChange={this.handleOptionsChange} />
                                </Col>
                            </FormGroup>
                            <FormGroup key="seconds" controlId="seconds" disabled={false}>
                                <Col sm={4}>
                                    <strong>Seconds</strong>
                                </Col>
                                <Col sm={8}>
                                    <FormControl type="integer" disabled={false} defaultValue={60} onChange={this.handleOptionsChange} />
                                </Col>
                            </FormGroup>
                            <FormGroup key="track" controlId="track" disabled={false}>
                                <Col sm={4}>
                                    <strong>Track by</strong>
                                </Col>
                                <Col sm={8}>
                                    <FormControl componentClass="select" placeholder="by_src" onChange={this.handleOptionsChange}>
                                        <option value="by_src">By Source</option>
                                        <option value="by_dst">By Destination</option>
                                    </FormControl>
                                </Col>
                            </FormGroup>
                        </React.Fragment>}
                        {this.props.action === 'tag' && <FormGroup key="tag" controlId="tag" disabled={false}>
                            <Col sm={3}>
                                <strong>Tag</strong>
                            </Col>
                            <Col sm={4}>
                                <FormControl componentClass="select" placeholder="relevant" onChange={this.handleOptionsChange}>
                                    <option value="relevant">Relevant</option>
                                    <option value="informational">Informational</option>
                                </FormControl>
                            </Col>
                        </FormGroup>}
                        {this.props.action === 'tagkeep' && <FormGroup key="tag" controlId="tag" disabled={false}>
                            <Col sm={3}>
                                <strong>Tag and Keep</strong>
                            </Col>
                            <Col sm={4}>
                                <FormControl componentClass="select" placeholder="relevant" onChange={this.handleOptionsChange}>
                                    <option value="relevant">Relevant</option>
                                    <option value="informational">Informational</option>
                                </FormControl>
                            </Col>
                        </FormGroup>}
                        <FormGroup controlId="ruleset" disabled={false}>
                            <Col sm={12}>
                                <label>Choose Ruleset(s)</label>
                                {this.props.rulesets && this.props.rulesets.map((ruleset) => (
                                    <div className="row" key={ruleset.pk}>
                                        <div className="col-sm-9">
                                            <label htmlFor={ruleset.pk}><input type="checkbox" id={ruleset.pk} name={ruleset.pk} onChange={this.handleChange} />{ruleset.name}</label>
                                            {ruleset.warnings && <div>{ruleset.warnings}</div>}
                                        </div>
                                    </div>
                                ))}
                            </Col>
                        </FormGroup>

                        <div className="form-group">
                            <div className="col-sm-9">
                                <strong>Optional comment</strong>
                                <textarea value={this.state.comment} cols={70} onChange={this.handleCommentChange} />
                            </div>
                        </div>
                    </Form>}
                    {this.state.noaction && <p>You need enough permissions and at least a filter supported by the ruleset backend to define an action</p>}
                </Modal.Body>
                <Modal.Footer>
                    <Button
                        bsStyle="default"
                        className="btn-cancel"
                        onClick={this.close}
                    >
                        Cancel
                    </Button>
                    {!this.state.noaction && <Button bsStyle="primary" onClick={this.submit}>
                        Submit
                    </Button>}
                </Modal.Footer>
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
};
