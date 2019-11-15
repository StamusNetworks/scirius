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
            startDate: null,
            endDate: null,
        }
    }

    onStandaloneSelect = (type, value) => {
        this.setState({
            [type]: value,
        });
    }

    disabledStartDate = (type, current) => {
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
                    showToday
                    format={getFormat(true)}
                    showOk={false}
                    timePicker={timePickerElement}
                    disabledDate={(value) => this.disabledStartDate('startDate', value)}
                    onSelect={(value) => this.onStandaloneSelect('startDate', value)}
                />
                <Calendar
                    className="calendar-end-date"
                    showWeekNumber={false}
                    format={getFormat(true)}
                    showToday
                    showOk={false}
                    timePicker={timePickerElement}
                    disabledDate={(value) => this.disabledStartDate('endDate', value)}
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
}

export default DateRangePicker;
