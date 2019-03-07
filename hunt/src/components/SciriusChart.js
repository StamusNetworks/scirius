/*
Copyright(C) 2018 Stamus Networks
Written by Eric Leblond <eleblond@stamus-networks.com>

This file is part of Scirius.

Scirius is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Scirius is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Scirius.  If not, see <http://www.gnu.org/licenses/>.
*/


import React from 'react';

const c3 = require('c3');

export default class SciriusChart extends React.Component {
    constructor(props) {
        super(props);
        // Generate unique ID for the chart
        this.chartId = `chart${Math.random().toString(36).substr(2, 9)}`;
    }

    componentDidMount() {
        this.chartRender(this.props);
    }

    componentWillReceiveProps(nextProps) {
        this.chartRender(nextProps);
    }

    chartRender = (opts) => {
        let _opts = {...opts};
        let axis = {
            x: {
                type: 'timeseries',
                localtime: true,
                min: opts.from_date,
                max: Date.now(),
                tick: {
                    fit: false,
                    rotate: 15,
                    format: '%Y-%m-%d %H:%M'
                }
            }
        }
        if (opts.axis) {
            if (opts.axis.x) {
                axis.x = {...axis.x, ...opts.axis.x};
            }
            if (opts.axis.y) {
                axis.y = opts.axis.y;
            }
            delete _opts.axis;
        }
        c3.generate({
            bindto: `#${this.chartId}`,
            axis: axis,
            ..._opts
        });
    }

    render() {
        return (<div id={this.chartId}>loading</div>);
    }
}
