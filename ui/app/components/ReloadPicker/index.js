/**
 *
 * ReloadPicker
 *
 */

import React from 'react';
import PropTypes from 'prop-types';
import { Button, Radio } from 'antd';
import { bindActionCreators, compose } from 'redux';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import styled from 'styled-components';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import { doReload, setReload } from 'ui/containers/App/actions';
import { makeSelectReload } from 'ui/containers/App/selectors';

const QuicksWrapper = styled.div`
  display: flex;
  flex-direction: column;
  align-items: center;
`;

const RadioOption = styled(Radio)`
  width: 200px;
  display: block !important;
  padding: 6px 10px !important;
  &:hover {
    background-color: #e6f7ff;
  }
`;

const ReloadPicker = ({ reloadPeriod, setReload, doReload }) => (
  <QuicksWrapper>
    <Radio.Group defaultValue="a" size="default">
      <Button type="primary" style={{ width: '100%' }} onClick={() => doReload()}>
        Reload Now
      </Button>
      {Object.keys(ReloadPeriodEnum).map(p => (
        <RadioOption
          value={ReloadPeriodEnum[p].seconds}
          checked={parseInt(p, 10) === reloadPeriod.period.seconds}
          key={p}
          name={ReloadPeriodEnum[p].title}
          onClick={() => setReload(ReloadPeriodEnum[p])}
        >
          {ReloadPeriodEnum[p].title}
        </RadioOption>
      ))}
    </Radio.Group>
  </QuicksWrapper>
);

ReloadPicker.propTypes = {
  reloadPeriod: PropTypes.object,
  setReload: PropTypes.func,
  doReload: PropTypes.func,
};

const mapStateToProps = createStructuredSelector({
  reloadPeriod: makeSelectReload(),
});

const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setReload,
      doReload,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);

export default compose(withConnect)(ReloadPicker);
