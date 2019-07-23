import React from 'react';
import PropTypes from 'prop-types';
import moment from 'moment';
import { connect } from 'react-redux';
import { Col, Icon, Row, ListViewItem, ListViewInfoItem, ListViewIcon } from 'patternfly-react';
import { PAGE_STATE } from 'hunt_common/constants';
import { sections, addFilter } from '../containers/App/stores/global';

const HistoryItem = (props) => {
    const date = moment(props.data.date).format('YYYY-MM-DD, hh:mm:ss a');
    const info = [<ListViewInfoItem key="date"><p>Date: {date}</p></ListViewInfoItem>,
        <ListViewInfoItem key="user"><p><Icon type="pf" name="user" /> {props.data.username}</p>
        </ListViewInfoItem>
    ];
    if (props.data.ua_objects.ruleset && props.data.ua_objects.ruleset.pk) {
        info.push(<ListViewInfoItem key="ruleset"><p><Icon type="fa" name="th" /> {props.data.ua_objects.ruleset.value}</p></ListViewInfoItem>);
    }
    if (props.data.ua_objects.rule && props.data.ua_objects.rule.sid) {
        // eslint-disable-next-line jsx-a11y/click-events-have-key-events
        info.push(<ListViewInfoItem key="rule">
            <p>
                <a
                    onClick={() => {
                        props.addFilter(sections.GLOBAL, { id: 'alert.signature_id', value: props.data.ua_objects.rule.sid, negated: false });
                        props.switchPage(PAGE_STATE.rules_list, props.data.ua_objects.rule.sid);
                    }}
                ><i className={'pficon-security'} /> {props.data.ua_objects.rule.sid}</a>
            </p>
        </ListViewInfoItem>);
    }
    return (
        <ListViewItem
            leftContent={<ListViewIcon name="envelope" />}
            additionalInfo={info}
            heading={props.data.title}
            description={props.data.description}
            key={props.data.pk}
            compoundExpand={props.expand_row}
            compoundExpanded
        >
            {props.data.comment && <Row>
                <Col sm={11}>
                    <div className="container-fluid">
                        <strong>Comment</strong>
                        <p>{props.data.comment}</p>
                    </div>
                </Col>
            </Row>}
        </ListViewItem>
    );
}

HistoryItem.propTypes = {
    data: PropTypes.any,
    switchPage: PropTypes.any,
    expand_row: PropTypes.any,
    addFilter: PropTypes.func,
};

const mapDispatchToProps = {
    addFilter,
};

export default connect(null, mapDispatchToProps)(HistoryItem);
