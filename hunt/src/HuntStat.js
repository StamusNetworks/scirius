import React from 'react';
import PropTypes from 'prop-types';
import { DropdownKebab, MenuItem } from 'patternfly-react';
import { Badge, ListGroup, ListGroupItem } from 'react-bootstrap';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from 'hunt_common/buildQFilter';
import EventValue from './components/EventValue';

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
        if (JSON.stringify(prevProps.filters) !== JSON.stringify(this.props.filters)) {
            this.updateData();
        }
    }

    updateData() {
        const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);

        this.url = `${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${this.props.item}&from_date=${this.props.from_date}&page_size=30${qfilter}`;

        axios.get(`${config.API_URL}${config.ES_BASE_PATH}field_stats/?field=${this.props.item}&from_date=${this.props.from_date}&page_size=5${qfilter}`)
        .then((res) => {
            this.setState({ data: res.data });
        });
    }

    addFilter(id, value, negated) {
        this.props.addFilter({ id, value, negated });
    }

    render() {
        let colVal = 'col-md-3';
        if (this.props.col) {
            colVal = `col-md-${this.props.col}`;
        }
        if (this.state.data && this.state.data.length) {
            return (
                <div className={colVal}>
                    <h3 className="hunt-stat-title truncate-overflow" data-toggle="tooltip" title={this.props.title}>{this.props.title}
                        {this.state.data.length === 5 && <DropdownKebab id={`more-${this.props.item}`} pullRight>
                            <MenuItem onClick={() => this.props.loadMore(this.props.item, this.url)} data-toggle="modal">Load more results</MenuItem>
                        </DropdownKebab>}
                    </h3>
                    <div className="hunt-stat-body">
                        <ListGroup>
                            {this.state.data.map((item) => (
                                <ListGroupItem key={item.key}>
                                    <EventValue field={this.props.item} value={item.key} addFilter={this.addFilter} right_info={<Badge>{item.doc_count}</Badge>} />
                                </ListGroupItem>)
                            )}
                        </ListGroup>
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
