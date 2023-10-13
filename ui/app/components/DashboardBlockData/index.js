import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';
import { CSSTransition, TransitionGroup } from 'react-transition-group';
import { KillChainStepsEnum } from 'ui/maps/KillChainStepsEnum';

const DashboardBlockData = ({ block, data, copyMode }) => (
  <TransitionGroup>
    {data?.map(item => (
      <CSSTransition key={item.key} nodeRef={item.nodeRef} timeout={500} classNames="item">
        <EventValue
          ref={item.nodeRef}
          key={item.key}
          field={block.i}
          value={(KillChainStepsEnum[item.key] && KillChainStepsEnum[item.key]) || item.key}
          right_info={<span className="badge">{item.doc_count}</span>}
          copyMode={copyMode}
          format={block.format}
        />
      </CSSTransition>
    ))}
  </TransitionGroup>
);

export default DashboardBlockData;

DashboardBlockData.propTypes = {
  block: PropTypes.shape({
    i: PropTypes.string,
    title: PropTypes.string,
    format: PropTypes.func,
  }),
  data: PropTypes.array.isRequired,
  copyMode: PropTypes.bool.isRequired,
};
