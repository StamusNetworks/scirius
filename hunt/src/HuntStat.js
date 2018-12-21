import React from 'react';
import PropTypes from 'prop-types';
import { DropdownKebab, MenuItem } from 'patternfly-react';
import { Badge, ListGroup, ListGroupItem } from 'react-bootstrap';
import axios from 'axios';
import { buildQFilter } from './helpers/buildQFilter';
import * as config from './config/Api';
import EventValue from './EventValue';

export default class HuntStat extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: [] };
        this.url = '';
        this.updateData = this.updateData.bind(this);
        this.addFilter = this.addFilter.bind(this);
    }

    componentDidMount() {
        this.updateData();
    }

    componentDidUpdate(prevProps) {
        if (prevProps.from_date !== this.props.from_date) {
            this.updateData();
        }
        if (prevProps.filters.length !== this.props.filters.length) {
            this.updateData();
        }
    }

    updateData() {
        let qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
        if (qfilter) {
            qfilter = `&qfilter=${qfilter}`;
        } else {
            qfilter = '';
        }

        this.url = `${config.API_URL}${config.ES_BASE_PATH}field_stats&field=${this.props.item}&from_date=${this.props.from_date}&page_size=30${qfilter}`;

        axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats&field=${this.props.item}&from_date=${this.props.from_date}&page_size=5${qfilter}`)
        .then((res) => {
            this.setState({ data: res.data });
        });
    }

    addFilter(key, value, negated) {
        this.props.addFilter(key, value, negated);
    }

    render() {
        let colVal = 'col-md-3';
        if (this.props.col) {
            colVal = `col-md-${this.props.col}`;
        }
        if (this.state.data && this.state.data.length) {
            return (
                <div className={colVal}>
                    <div className="card-pf rule-card">
                        <div className="card-pf-heading">
                            <h2 className="card-pf-title truncate-overflow" data-toggle="tooltip" title={this.props.title}>{this.props.title}</h2>
                            {this.state.data.length === 5 && <DropdownKebab id={`more-${this.props.item}`} pullRight={false}>
                                <MenuItem onClick={() => this.props.loadMore(this.props.item, this.url)} data-toggle="modal">Load more results</MenuItem>
                            </DropdownKebab>}
                        </div>
                        <div className="card-pf-body">
                            <ListGroup>
                                {this.state.data.map((item) => (
                                    <ListGroupItem key={item.key}>
                                        <EventValue field={this.props.item} value={item.key} addFilter={this.addFilter} right_info={<Badge>{item.doc_count}</Badge>} />
                                    </ListGroupItem>)
                                )}
                            </ListGroup>
                        </div>
                    </div>
                </div>
            );
        }
        return null;
    }
}
HuntStat.propTypes = {
    from_date: PropTypes.any,
    title: PropTypes.any,
    filters: PropTypes.any,
    col: PropTypes.any,
    item: PropTypes.any,
    systemSettings: PropTypes.any,
    loadMore: PropTypes.func,
    addFilter: PropTypes.func,
};
