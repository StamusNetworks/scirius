/* eslint-disable react/no-danger */
import React from 'react';
import PropTypes from 'prop-types';
import { Badge, ListGroup, ListGroupItem } from 'react-bootstrap';
import { Col, Icon, Row, Spinner, ListViewIcon, ListViewInfoItem, ListViewItem } from 'patternfly-react';
import RuleEditKebab from './RuleEditKebab';
import SciriusChart from './SciriusChart';
import EventValue from './EventValue';

const RuleInList = (props) => {
    const { category } = props.data;
    const source = props.state.sources[category.source];
    let catTooltip = category.name;
    if (source && source.name) {
        catTooltip = `${source.name}: ${category.name}`;
    }
    const kebabConfig = { rule: props.data };
    return (
        <ListViewItem
            key={props.data.sid}
            // eslint-disable-next-line jsx-a11y/click-events-have-key-events,jsx-a11y/no-static-element-interactions,jsx-a11y/interactive-supports-focus
            actions={[<a role="button" key={`actions-${props.data.sid}`} onClick={() => { props.SwitchPage(props.data); }}><Icon type="fa" name="search-plus" /> </a>, <RuleEditKebab key={`kebab-${props.data.sid}`} config={kebabConfig} rulesets={props.rulesets} />]}
            leftContent={<ListViewIcon name="envelope" />}
            additionalInfo={[<ListViewInfoItem key={`created-${props.data.sid}`}><p>Created: {props.data.created}</p></ListViewInfoItem>,
                <ListViewInfoItem key={`updated-${props.data.sid}`}><p>Updated: {props.data.updated}</p></ListViewInfoItem>,
                <ListViewInfoItem key={`category-${props.data.sid}`}><p data-toggle="tooltip" title={catTooltip}>Category: {category.name}</p></ListViewInfoItem>,
                <ListViewInfoItem key={`hits-${props.data.sid}`}><Spinner loading={props.data.hits === undefined} size="xs"><p>Alerts <span className="badge">{props.data.hits}</span></p></Spinner></ListViewInfoItem>
            ]}
            heading={props.data.sid}
            description={props.data.msg}
        >
            {props.data.timeline && <Row>
                <Col sm={11}>
                    <div className="container-fluid">
                        <div className="row">
                            <div className="SigContent" dangerouslySetInnerHTML={{ __html: props.data.content }}></div>
                        </div>
                        <div className="row">
                            <div className="col-md-12">
                                <SciriusChart data={props.data.timeline}
                                    axis={{
                                        x: {
                                            type: 'timeseries',
                                            localtime: true,
                                            min: props.from_date,
                                            max: Date.now(),
                                            tick: { fit: false, rotate: 15, format: '%Y-%m-%d %H:%M' }
                                        }
                                    }}
                                />
                            </div>
                        </div>
                        <div className="row">
                            <div className="col-md-4">
                                <h4>Probes</h4>
                                <ListGroup>
                                    {props.data.probes.map((item) => (
                                        <ListGroupItem key={item.probe}>
                                            <EventValue field={'host'} value={item.probe} addFilter={props.addFilter} right_info={<Badge>{item.hits}</Badge>} />
                                        </ListGroupItem>))}
                                </ListGroup>
                            </div>
                        </div>
                    </div>
                </Col>
            </Row>}
        </ListViewItem>
    );
}

RuleInList.propTypes = {
    data: PropTypes.any,
    state: PropTypes.any,
    rulesets: PropTypes.any,
    from_date: PropTypes.any,
    SwitchPage: PropTypes.any,
    addFilter: PropTypes.any,
};

export default RuleInList;
