import React from 'react';
import PropTypes from 'prop-types';
import moment from 'moment';
import Calendar from 'rc-calendar';
import 'rc-time-picker/assets/index.css';
import TimePickerPanel from 'rc-time-picker/lib/Panel';
import 'rc-calendar/assets/index.css';

const format = 'YYYY-MM-DD HH:mm:ss';
function getFormat(time) {
    return time ? format : 'YYYY-MM-DD';
}

const timePickerElement = <TimePickerPanel defaultValue={moment('00:00:00', 'HH:mm:ss')} />;

class DateRangePicker extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            startDate: (props.selectedFromDate === null) ? moment() : moment(props.selectedFromDate),
            endDate: (props.selectedToDate === null) ? moment() : moment(props.selectedToDate),
        }
    }

    onStandaloneSelect = (type, value) => {
        this.setState({
            [type]: value,
        });
    }

    disabledDate = (type, current) => {
        const { endDate, startDate } = this.state;
        if (!current) {
            return false;
        }
        if (type === 'startDate' && endDate !== null) {
            return current.valueOf() > endDate.valueOf(); // can not select days before today
        }
        if (type === 'endDate' && startDate !== null) {
            return current.valueOf() < startDate.valueOf(); // can not select days before today
        }
        return false;
    }

    render() {
        return <div style={{ display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', flexDirection: 'row' }}>
                <Calendar
                    className="calendar-start-date"
                    showWeekNumber={false}
                    format={getFormat(true)}
                    showOk={false}
                    timePicker={timePickerElement}
                    defaultValue={this.state.startDate}
                    disabledDate={(value) => this.disabledDate('startDate', value)}
                    onSelect={(value) => this.onStandaloneSelect('startDate', value)}
                />
                <Calendar
                    className="calendar-end-date"
                    showWeekNumber={false}
                    format={getFormat(true)}
                    showOk={false}
                    timePicker={timePickerElement}
                    defaultValue={this.state.endDate}
                    disabledDate={(value) => this.disabledDate('endDate', value)}
                    onSelect={(value) => this.onStandaloneSelect('endDate', value)}
                />
            </div>
            <div className="submit-date">
                <a href="#" onClick={() => this.props.onOk(this.state.startDate, this.state.endDate)}>Submit</a>
            </div>
        </div>
    }
}

DateRangePicker.propTypes = {
    onOk: PropTypes.any,
    selectedFromDate: PropTypes.any,
    selectedToDate: PropTypes.any,
}

DateRangePicker.defaultProps = {
    selectedFromDate: null,
    selectedToDate: null,
}
export default DateRangePicker;
