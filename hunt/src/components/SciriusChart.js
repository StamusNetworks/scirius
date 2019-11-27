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
import PropTypes from 'prop-types';
import DeepExtend from 'deep-extend';

const c3 = require('c3');

export default class SciriusChart extends React.Component {
    constructor(props) {
        super(props);
        // Generate unique ID for the chart
        this.chartId = `chart${Math.random().toString(36).substr(2, 9)}`;
        this.chart = null;
        const labelWidth = 54;
        const labelPadding = 20 * 2;
        this.state = {
            labelsCount: 0,
            labelWidth,
            labelPadding,
        }
        this.deepProps = {
            axis: {
                x: {
                    type: 'timeseries',
                    localtime: true,
                    show: true,
                    tick: {
                        outer: false,
                        format: '%Y-%m-%d %H:%M',
                        multiline: true,
                        multilineMax: 5,
                        width: labelWidth,
                        fit: true,
                        values: [],
                    },
                },
                y: {
                    tick: {
                        count: 5
                    },
                    min: 0,
                },
            },
            padding: {
                right: 30
            },
            data: {},
        };
        this.mounted = false;
        DeepExtend(this.deepProps, { ...props });
    }

    componentDidMount() {
        this.mountChart();
    }

    componentWillReceiveProps(nextProps) {
        const labelsLimit = this.getLabelsLimit();
        if (this.state.labelsCount !== labelsLimit) {
            this.setState(({
                ...this.state,
                labelsCount: labelsLimit
            }))
        }
        DeepExtend(this.deepProps, nextProps);
    }

    shouldComponentUpdate(nextProps, nextState) {
        return !(JSON.stringify(nextProps) === JSON.stringify(this.props) && JSON.stringify(nextState) === JSON.stringify(this.state));
    }

    componentDidUpdate() {
        this.mountChart();
    }

    componentWillUnmount() {
        this.deepProps = {};
        this.chart.destroy();
    }

    /* return width of the graph without X axis field */
    getGraphWidth = () => {
        const width = document.querySelector(`#${this.chartId}`);
        return (typeof width !== 'undefined' && width !== null) ? width.clientWidth - 40 : 0;
    }

    getLabelsLimit = () => {
        const graphWidth = this.getGraphWidth();
        return (graphWidth > 0) ? Math.floor(graphWidth / (this.state.labelWidth + this.state.labelPadding)) : 0;
    }

    getChartProperties = () => {
        if (this.deepProps.axis.x.show) {
            DeepExtend(this.deepProps, this.formatXLabels())
        }
        return this.deepProps;
    }

    mountChart = () => {
        this.chart = c3.generate({
            bindto: `#${this.chartId}`,
            ...this.getChartProperties()
        });
    }

    formatXLabels = () => {
        const allowedIntervals = [
            60 * 1000, /* 1 min  */
            5 * 60 * 1000, /* 5 mins  */
            10 * 60 * 1000, /* 10 mins */
            30 * 60 * 1000, /* 30 mins */
            60 * 60 * 1000, /* 1 hour */
            90 * 60 * 1000, /* 1.5 hours */
            2 * 60 * 60 * 1000, /* 2 hours */
            3 * 60 * 60 * 1000, /* 3 hours */
            4 * 60 * 60 * 1000, /* 4 hours */
            6 * 60 * 60 * 1000, /* 6 hours */
            8 * 60 * 60 * 1000, /* 8 hours */
            10 * 60 * 60 * 1000, /* 10 hours */
            12 * 60 * 60 * 1000, /* 12 hours */
            14 * 60 * 60 * 1000, /* 14 hours */
            16 * 60 * 60 * 1000, /* 16 hours */
            18 * 60 * 60 * 1000, /* 18 hours */
            20 * 60 * 60 * 1000, /* 20 hours */
            22 * 60 * 60 * 1000, /* 22 hours */
            24 * 60 * 60 * 1000, /* 1 day */
            36 * 60 * 60 * 1000, /* 1.5 days */
            3 * 24 * 60 * 60 * 1000, /* 3  days */
            5 * 24 * 60 * 60 * 1000, /* 5  days */
            7 * 24 * 60 * 60 * 1000, /* 7  days */
            14 * 24 * 60 * 60 * 1000, /* 14  days */
            30 * 24 * 60 * 60 * 1000, /* 30  days */
        ];
        const ticks = [];
        let yAxis = [];
        if (this.deepProps.axis.x.show) {
            let tickMin = this.deepProps.axis.x.min;
            const tickMax = this.deepProps.axis.x.max;

            let tickCount = 0;
            let interval = 0;

            const timespan = tickMax - tickMin;
            const labelOuterWidth = this.state.labelWidth + this.state.labelPadding;
            const getGraphWidth = this.getGraphWidth();
            for (let g = 0; g < allowedIntervals.length; g += 1) {
                if ((timespan / allowedIntervals[g]) * labelOuterWidth < getGraphWidth) {
                    interval = allowedIntervals[g];
                    break;
                }
            }

            tickMin = (Math.ceil(this.deepProps.axis.x.min / interval) * interval);
            while (tickMax > tickCount * interval + tickMin) {
                ticks.push((tickCount * interval) + tickMin);
                tickCount += 1;
            }

            // Display pretty Y axis
            let xAxesMaxVal = 0;
            const xAxesValues = JSON.parse(JSON.stringify(this.deepProps.data.columns));
            for (let x = 0; x < xAxesValues.length; x += 1) {
                if (xAxesValues[x][0] !== 'x') {
                    xAxesValues[x].shift();
                    const axisMaxVal = Math.max(...xAxesValues[x]);
                    xAxesMaxVal = (xAxesMaxVal < axisMaxVal) ? axisMaxVal : xAxesMaxVal;
                }
            }
            const yLabelsCount = 5;
            const yInterval = Math.ceil(xAxesMaxVal / yLabelsCount);
            yAxis = new Array(yLabelsCount).fill(0);
            yAxis = yAxis.map((v, i) => (i + 1) * yInterval);
            yAxis.unshift(0);
        }

        return {
            axis: {
                x: {
                    tick: {
                        values: ticks
                    }
                },
                y: {
                    tick: {
                        values: yAxis
                    }
                },
            }
        };
    }

    render() {
        return (<div id={this.chartId}>loading</div>);
    }
}

SciriusChart.propTypes = {
    axis: PropTypes.shape({
        x: PropTypes.shape({
            type: PropTypes.string,
            localtime: PropTypes.bool,
            min: PropTypes.number,
            max: PropTypes.number,
            show: PropTypes.bool,
            tick: PropTypes.shape({
                format: PropTypes.string,
                multiline: PropTypes.bool,
                multilineMax: PropTypes.number,
                width: PropTypes.number,
                fit: PropTypes.bool,
                values: PropTypes.array,
            }),
        }),
        y: PropTypes.object,
    }),
}
