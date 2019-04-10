import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from './helpers/buildQFilter';
import ErrorHandler from './components/Error';
import DonutChart from './components/DonutChart';

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
            stringFilters += `&qfilter=${qfilter.replace('&qfilter=', '&filter=')}`;
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
                <ErrorHandler>
                    <DonutChart
                        data={{
                            columns: gData.columns,
                            groups: gData.groups,
                            colors: {
                                'previous count': '#0088ce',
                                'current count': '#737373'
                            },
                        }}
                        legend={{
                            show: true,
                            position: 'bottom',
                        }}
                        style={{
                            width: '190px',
                            height: '190px',
                        }}
                        donutWidth={12}
                        title={{
                            show: true,
                            pretty: true,
                            line1: this.state.data ? this.state.data.doc_count : 0,
                            line2: 'current count'
                        }}
                        tooltip={{
                            show: true
                        }}
                    />
                </ErrorHandler>
            </div>
        );
    }
}
HuntTrend.propTypes = {
    from_date: PropTypes.any,
    filters: PropTypes.any,
    systemSettings: PropTypes.any,
};
