import React from 'react';
import PropTypes from 'prop-types';
import { DonutChart } from 'patternfly-react';
import axios from 'axios';
import { buildQFilter } from './helpers/buildQFilter';
import * as config from './config/Api';

export default class HuntTrend extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: undefined };
        this.fetchData = this.fetchData.bind(this);
    }

    componentDidMount() {
        this.fetchData();
    }

    componentDidUpdate(prevProps) {
        if ((prevProps.from_date !== this.props.from_date) || (prevProps.filters !== this.props.filters)) {
            this.fetchData();
        }
    }

    fetchData() {
        let stringFilters = '';
        const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
        if (qfilter) {
            stringFilters += `&filter=${qfilter}`;
        }
        axios.get(`${config.API_URL}${config.ES_BASE_PATH}alerts_count&prev=1&hosts=*&from_date=${this.props.from_date}${stringFilters}`)
        .then((res) => {
            if (typeof (res.data) !== 'string') {
                this.setState({ data: res.data });
            }
        });
    }

    render() {
        let gData;
        if (this.state.data) {
            gData = {
                columns: [
                    ['previous count', this.state.data.prev_doc_count],
                    ['current count', this.state.data.doc_count]
                ],
                groups: [
                    ['previous count', 'current count']
                ]
            };
        } else {
            gData = {
                columns: [
                    ['previous count', 0],
                    ['current count', 0]
                ],
                groups: [
                    ['previous count', 'current count']
                ]
            };
        }
        return (
            <div>
                <DonutChart
                    data={gData}
                    title={{ type: 'max' }}
                    tooltip={{ show: true }}
                    legend={{ show: true, position: 'bottom' }}
                />
            </div>
        );
    }
}
HuntTrend.propTypes = {
    from_date: PropTypes.any,
    filters: PropTypes.any,
    systemSettings: PropTypes.any,
};
