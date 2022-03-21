import React from 'react';
import { compose } from 'redux';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import { Col, DropdownButton, FormControl, FormGroup, Icon, InputGroup, MenuItem, Row } from 'patternfly-react';
import moment from 'moment';
import * as PropTypes from 'prop-types';
import OutsideClickHandler from 'react-outside-click-handler';
import axios from 'axios';
import { API_URL, ES_BASE_PATH } from 'config/Api';
import DateRangePicker from './DateRangePicker';
import {
  filterTimeSpanSet,
  filterDurationSet,
  reducer,
  makeSelectFilterParam,
  makeSelectFilterAbsolute,
} from '../containers/App/stores/filterParams';
import { makeSelectGlobalFilters } from '../containers/App/stores/global';
import injectReducer from '../util/injectReducer';
import { periodShortener, USER_PERIODS } from '../helpers/PeriodShortener';

const moments = [
  { label: 'Please select' },
  { label: 'Seconds ago', get: (val) => moment().second(moment().second() - val) },
  { label: 'Minutes ago', get: (val) => moment().minute(moment().minute() - val) },
  { label: 'Hours ago', get: (val) => moment().hour(moment().hour() - val) },
  { label: 'Days ago', get: (val) => moment().date(moment().date() - val) },
  { label: 'Weeks ago', get: (val) => moment().week(moment().week() - val) },
  { label: 'Months ago', get: (val) => moment().month(moment().month() - val) },
  { label: 'Years ago', get: (val) => moment().year(moment().year() - val) },
  { label: 'Seconds from now', get: (val) => moment().second(moment().second() + val) },
  { label: 'Minutes from now', get: (val) => moment().minute(moment().minute() + val) },
  { label: 'Hours from now', get: (val) => moment().hour(moment().hour() + val) },
  { label: 'Days from now', get: (val) => moment().date(moment().date() + val) },
  { label: 'Weeks from now', get: (val) => moment().week(moment().week() + val) },
  { label: 'Months from now', get: (val) => moment().month(moment().month() + val) },
  { label: 'Years from now', get: (val) => moment().year(moment().year() + val) },
];

const PICKERS = {
  PREDEFINED: 1,
  ABSOLUTE: 2,
  RELATIVE: 3,
};
class TimeSpanItem extends React.Component {
  constructor(props) {
    super(props);
    this.format = 'MMMM Do YYYY, HH:mm:ss';

    this.state = {
      minTime: 0, // used by the `All` timerange
      maxTime: 0, // used by the `All` timerange
      picker: PICKERS.PREDEFINED,
      timeSpanPicker: false,
      ...props.absolute,
    };
  }

  async getAlertsTimerange() {
    const { data } = await axios.get(`${API_URL}${ES_BASE_PATH}alerts_timerange`);
    if (data.min_timestamp && data.max_timestamp) {
      this.setState({ minTime: data.min_timestamp, maxTime: data.max_timestamp });
    }
  }

  componentDidMount() {
    this.getAlertsTimerange();
  }

  componentDidUpdate(prevProps) {
    if (prevProps.tenant !== this.props.tenant || JSON.stringify(prevProps.globalFilters) !== JSON.stringify(this.props.globalFilters))
      this.getAlertsTimerange();

    if (
      JSON.stringify(prevProps.absolute) !== JSON.stringify(this.props.absolute) &&
      JSON.stringify(this.props.absolute) !== JSON.stringify({ from: this.state.from, to: this.state.to })
    ) {
      this.updateState();
    }
  }

  updateState = () => {
    this.setState({
      from: this.props.absolute.from,
      to: this.props.absolute.to,
    });
  };

  updateRelativeTime = (type, typeState) => {
    let time = typeState.value ? moments[typeState.id].get(typeState.value) : moment();
    if (typeState.roundChecked) {
      time = time.seconds(0);
    }
    this.setState({
      [type]: {
        ...typeState,
        time,
      },
    });
  };

  renderInputField = (type) => (
    <FormControl
      type="number"
      disabled={this.state[type].id === 0}
      style={{ width: '100px' }}
      min={1}
      value={this.state[type].value === 0 ? '' : this.state[type].value}
      onChange={(e) => {
        const typeState = {
          ...this.state[type],
          value: e.target.value === '' ? 0 : Math.abs(parseInt(e.target.value, 10)),
        };
        this.updateRelativeTime(type, typeState);
      }}
    />
  );

  renderDropDownField = (type) => (
    <DropdownButton id="input-dropdown-addon" title={moments[this.state[type].id].label} style={{ width: '135px' }}>
      {Object.keys(moments).map((i) => (
        <MenuItem
          key={`${type}-${moments[i].label}`}
          onClick={() => {
            const typeState = {
              ...this.state[type],
              id: parseInt(i, 10),
              now: false,
            };
            this.updateRelativeTime(type, typeState);
          }}
        >
          {moments[i].label}
        </MenuItem>
      ))}
    </DropdownButton>
  );

  renderSetToNow = (type) => (
    <a
      href="#"
      onClick={(e) => {
        e.preventDefault();
        this.setState({
          [type]: {
            ...this.state[type],
            now: !this.state[type].now,
            time: moment(),
            disabled: true,
            id: 0,
            value: 0,
          },
        });
      }}
    >
      {this.state[type].now ? 'x' : 'Set to now'}
    </a>
  );

  renderRounder = (type) => (
    <React.Fragment>
      <input
        type="checkbox"
        id={`${type}-RoundToSecs`}
        onClick={(e) => {
          const typeState = {
            ...this.state[type],
            roundChecked: e.target.checked,
          };
          this.updateRelativeTime(type, typeState);
        }}
      />{' '}
      <label htmlFor={`${type}-RoundToSecs`}>Round to seconds</label>
    </React.Fragment>
  );

  render() {
    return (
      <li>
        <div
          tabIndex={0}
          data-toggle="tooltip"
          title="Picker"
          onClick={(e) => {
            e.preventDefault();
            this.setState((prevState) => ({
              timeSpanPicker: !prevState.timeSpanPicker,
            }));
          }}
          role="button"
          className="nav-item-iconic"
          style={{ paddingTop: '23px', cursor: 'pointer' }}
        >
          <Icon type="fa" name="clock-o" />
          &nbsp;{periodShortener(this.props.fromDate, this.props.toDate, this.props.duration)}
        </div>

        {this.state.timeSpanPicker && (
          <div className="timespan-picker">
            <OutsideClickHandler onOutsideClick={() => this.setState((prevState) => ({ timeSpanPicker: !prevState.timeSpanPicker }))}>
              <ul className="time-pickers">
                <li>
                  <a
                    href="#"
                    className={`picker ${this.state.picker === PICKERS.PREDEFINED ? 'active' : ''}`}
                    onMouseOver={() => this.setState({ picker: PICKERS.PREDEFINED })}
                  >
                    Quick
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className={`picker ${this.state.picker === PICKERS.ABSOLUTE ? 'active' : ''}`}
                    onMouseOver={() => this.setState({ picker: PICKERS.ABSOLUTE })}
                  >
                    Absolute
                  </a>
                </li>
                <li>
                  <a
                    href="#"
                    className={`picker ${this.state.picker === PICKERS.RELATIVE ? 'active' : ''}`}
                    onMouseOver={() => this.setState({ picker: PICKERS.RELATIVE })}
                  >
                    Relative
                  </a>
                </li>
              </ul>
              <div style={{ clear: 'both' }} />
              <div className="pickers-content">
                <div className={`picker ${this.state.picker === PICKERS.PREDEFINED ? 'active' : ''}`}>
                  <ul className="hardcoded-stamps">
                    {Object.keys(USER_PERIODS).map((period) => (
                      <li key={period}>
                        <a
                          className={this.props.duration === period || (this.props.duration === null && !parseInt(period, 10)) ? 'active' : ''}
                          href="#"
                          onClick={() => {
                            if (USER_PERIODS[period] !== USER_PERIODS.all) {
                              this.props.setDuration(period);
                            } else {
                              if (!this.state.minTime || !this.state.maxTime) return;
                              this.getAlertsTimerange();
                              this.props.setTimeSpan({
                                fromDate: this.state.minTime,
                                toDate: this.state.maxTime,
                              });
                            }
                          }}
                        >
                          {USER_PERIODS[period] !== USER_PERIODS.all ? 'Last' : ''} {USER_PERIODS[period]}
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className={`picker ${this.state.picker === PICKERS.ABSOLUTE ? 'active' : ''}`}>
                  <DateRangePicker
                    selectedFromDate={this.props.fromDate}
                    selectedToDate={this.props.toDate}
                    onOk={(from, to) => {
                      this.props.setTimeSpan({
                        fromDate: Math.round(from.unix() * 1000),
                        toDate: Math.round(to.unix() * 1000),
                      });
                    }}
                  />
                </div>
                <div className={`picker ${this.state.picker === PICKERS.RELATIVE ? 'active' : ''}`}>
                  <Row className="relative-stamps ">
                    <Col md={6} className="from">
                      <Row className="no-row">
                        <Col md={6}>From</Col>
                        <Col md={6} className="set-to-now">
                          {this.renderSetToNow('from')}
                        </Col>
                      </Row>
                      <div style={{ clear: 'both' }} />
                      <div className="time-label">{this.state.from.time.format(this.format)}</div>
                      <FormGroup controlId="control-6">
                        <InputGroup>
                          {this.renderInputField('from')}
                          {this.renderDropDownField('from')}
                        </InputGroup>
                      </FormGroup>
                      {!this.state.from.now && this.renderRounder('from')}
                    </Col>
                    <Col md={6} className="to">
                      <Row className="no-gutter">
                        <Col md={6}>To</Col>
                        <Col md={6} className="set-to-now">
                          {this.renderSetToNow('to')}
                        </Col>
                      </Row>
                      <div style={{ clear: 'both' }} />
                      <div className="time-label">{this.state.to.time.format(this.format)}</div>
                      <FormGroup controlId="control-7">
                        <InputGroup>
                          {this.renderInputField('to')}
                          {this.renderDropDownField('to')}
                        </InputGroup>
                      </FormGroup>
                      {!this.state.to.now && this.renderRounder('to')}
                    </Col>
                  </Row>
                  <Row>
                    <div style={{ textAlign: 'center', padding: '15px 15px 0px', borderTop: '1px solid #e9e9e9', marginTop: '8px' }}>
                      <a
                        href="#"
                        onClick={(e) => {
                          e.preventDefault();
                          const from = this.state.from.time;
                          const to = this.state.to.time;
                          if (from.unix() >= to.unix()) {
                            /* eslint-disable-next-line no-alert */
                            alert(
                              `From cannot be greater or equal to To! \nCurrent selected dates: \nFrom: ${from.format(this.format)} \nTo: ${to.format(
                                this.format,
                              )}`,
                            );
                          } else {
                            this.props.setTimeSpan({
                              fromDate: Math.round(from.unix() * 1000),
                              toDate: Math.round(to.unix() * 1000),
                              absolute: {
                                from: { ...this.state.from },
                                to: { ...this.state.to },
                              },
                            });
                          }
                        }}
                      >
                        Submit
                      </a>
                    </div>
                  </Row>
                </div>
              </div>
            </OutsideClickHandler>
          </div>
        )}
      </li>
    );
  }
}

TimeSpanItem.propTypes = {
  setTimeSpan: PropTypes.func,
  setDuration: PropTypes.func,
  fromDate: PropTypes.any,
  toDate: PropTypes.any,
  duration: PropTypes.any,
  absolute: PropTypes.object,
  tenant: PropTypes.number,
  globalFilters: PropTypes.arrayOf(PropTypes.object),
};

const mapStateToProps = createStructuredSelector({
  fromDate: makeSelectFilterParam('fromDate'),
  toDate: makeSelectFilterParam('toDate'),
  duration: makeSelectFilterParam('duration'),
  absolute: makeSelectFilterAbsolute(),
  tenant: makeSelectFilterParam('tenant'),
  globalFilters: makeSelectGlobalFilters(),
});

const mapDispatchToProps = (dispatch) => ({
  setTimeSpan: (timespan) => dispatch(filterTimeSpanSet(timespan)),
  setDuration: (duration) => dispatch(filterDurationSet(duration)),
});

const withConnect = connect(mapStateToProps, mapDispatchToProps);
const withReducer = injectReducer({ key: 'filterParams', reducer });

export default compose(withReducer, withConnect)(TimeSpanItem);
