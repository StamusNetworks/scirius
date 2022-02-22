import React from 'react';
import PropTypes from 'prop-types';
import { Button, Radio } from 'antd';
import { bindActionCreators, compose } from 'redux';
import { connect } from 'react-redux';
import { createStructuredSelector } from 'reselect';
import styled from 'styled-components';
import { ReloadPeriodEnum } from 'ui/maps/ReloadPeriodEnum';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';

const QuicksWrapper = styled.div`
  width: 240px;

  & button {
    margin-bottom: 10px;
  }

  & label {
    display: grid;
    grid-template-columns: min-content 1fr min-content;
    cursor: pointer;
    align-items: center;
    height: 32px;
    margin-right: 0px;
    & > span {
      height: 32px;
      padding: 5px 8px;
    }
  }
  .ant-radio-wrapper-checked {
    background: #bcccd1;
  }

  & label:hover {
    background: #f0f2f5;
  }

  & > .ant-radio-group {
    display: flex;
    flex-direction: column;
  }

  & .ant-radio-checked::after {
    border: none;
    animation: none;
  }
`;

const ReloadPicker = ({ reloadPeriod, setReload, doReload }) => (
  <QuicksWrapper>
      <Radio.Group defaultValue={ReloadPeriodEnum.NONE.seconds} size="default">
        <Button type="primary" onClick={() => doReload()}>
          Reload Now
        </Button>
        {Object.keys(ReloadPeriodEnum).map(p => (
          <Radio
            value={ReloadPeriodEnum[p].seconds}
            checked={parseInt(p, 10) === reloadPeriod.period.seconds}
            key={p}
            name={ReloadPeriodEnum[p].title}
            onClick={() => setReload(ReloadPeriodEnum[p])}
          >
            {ReloadPeriodEnum[p].title}
          </Radio>
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
  reloadPeriod: selectors.makeSelectReload(),
});

const mapDispatchToProps = dispatch =>
  bindActionCreators(
    {
      setReload: actions.setReload,
      doReload: actions.doReload,
    },
    dispatch,
  );

const withConnect = connect(
  mapStateToProps,
  mapDispatchToProps,
);

export default compose(withConnect)(ReloadPicker);
