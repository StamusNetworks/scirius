import React from 'react';
import PropTypes from 'prop-types';
import { DonutChart } from 'patternfly-react';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from './helpers/buildQFilter';

export default class HuntTrend extends React.Component {
    constructor(props) {
        super(props);
        this.state = { data: undefined };
        this.fetchData = this.fetchData.bind(this);
        this.bigNumFormatter = this.bigNumFormatter.bind(this);
        this.formatDonutNumber = this.formatDonutNumber.bind(this);
    }

    componentDidMount() {
        this.fetchData();
        this.formatDonutNumber();
    }

    componentDidUpdate(prevProps) {
        if ((prevProps.from_date !== this.props.from_date) || (prevProps.filters !== this.props.filters)) {
            this.fetchData();
        }
        this.formatDonutNumber();
    }

    // eslint-disable-next-line class-methods-use-this
    bigNumFormatter(number) {
        let res = number.toString();
        if (number > 999999999) {
            res = `${(number / 1000000000).toFixed(1)}B`;
        } else if (number > 999999) {
            res = `${(number / 1000000).toFixed(1)}M`;
        } else if (number > 999) {
            res = `${(number / 1000).toFixed(1)}k`;
        }
        return res;
    }

    formatDonutNumber() {
        let count = parseInt(document.querySelector('.donut-title-big-pf').innerHTML, 10);
        count = this.bigNumFormatter(count);
        document.querySelector('.donut-title-big-pf').innerHTML = count;
    }

    fetchData() {
        let stringFilters = '';
        const qfilter = buildQFilter(this.props.filters, this.props.systemSettings);
        if (qfilter) {
            stringFilters += `&qfilter=${qfilter.replace('&host_id_qfilter=', '')}`;
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
                    size={{ width: 190, height: 190 }}
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
