import React from 'react';
import PropTypes from 'prop-types';
import axios from 'axios';
import * as config from 'hunt_common/config/Api';
import { buildQFilter } from './helpers/buildQFilter';
import SciriusChart from './components/SciriusChart';
import ErrorHandler from './components/Error';

export default class HuntTimeline extends React.Component {
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
            stringFilters += `&filter=${qfilter.replace('&qfilter=', '')}`;
        }
        axios.get(`${config.API_URL}${config.ES_BASE_PATH}timeline/?hosts=*&from_date=${this.props.from_date}${stringFilters}`)
        .then((res) => {
            /* iterate on actual row: build x array, for each row build hash x -> value */
            /* sort x array */
            /* for key in x array, build each row, value if exists, 0 if not */
            const prows = { x: [] };

            const keys = Object.keys(res.data);
            const vals = Object.values(res.data);
            let key;
            for (let keyNum = 0; keyNum < keys.length; keyNum += 1) {
                key = keys[keyNum];
                if (!(['interval', 'from_date'].includes(key))) {
                    prows[key] = {};
                    for (let entry = 0; entry < vals[keyNum].entries.length; entry += 1) {
                        if (prows.x.indexOf(vals[keyNum].entries[entry].time) === -1) {
                            prows.x.push(vals[keyNum].entries[entry].time);
                        }
                        prows[key][vals[keyNum].entries[entry].time] = vals[keyNum].entries[entry].count;
                    }
                }
            }

            const pprows = prows.x.slice();
            pprows.sort((a, b) => a - b);
            let putindrows = [''];
            putindrows[0] = pprows;
            putindrows[0].unshift('x');
            const pKeys = Object.keys(prows);
            let k;
            for (let pki = 0; pki < pKeys.length; pki += 1) {
                k = pKeys[pki];
                if (k !== 'x') {
                    const pvalue = [k];
                    for (let i = 1; i < putindrows[0].length; i += 1) {
                        if (putindrows[0][i] in prows[k]) {
                            pvalue.push(prows[k][putindrows[0][i]]);
                        } else {
                            pvalue.push(0);
                        }
                    }
                    putindrows.push(pvalue);
                }
            }
            if (putindrows.length === 1) {
                putindrows = [];
            }
            this.setState({ data: { x: 'x', columns: putindrows } });
        });
    }

    render() {
        return (
            <div style={{ ...this.props.style }}>
                {this.state.data && <ErrorHandler><SciriusChart data={this.state.data}
                    from_date={this.props.from_date}
                    padding={{ bottom: 15 }}
                    size={{ height: 200 }}
                /></ErrorHandler>}
            </div>
        );
    }
}

HuntTimeline.defaultProps = {
    style: {}
}

HuntTimeline.propTypes = {
    filters: PropTypes.any,
    systemSettings: PropTypes.any,
    from_date: PropTypes.any,
    style: PropTypes.object,
};
