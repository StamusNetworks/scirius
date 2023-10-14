import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';
import { CSSTransition, TransitionGroup } from 'react-transition-group';
import Filter from 'ui/utils/Filter';

const DashboardBlockData = ({ block, data, copyMode }) => (
  <TransitionGroup>
    {data?.map(item => (
      <CSSTransition key={item.key} nodeRef={item.nodeRef} timeout={500} classNames="item">
        <EventValue
          key={item.key}
          ref={item.nodeRef}
          filter={new Filter(block.i, item.key)}
          count={<span className="badge">{item.doc_count}</span>}
          copyMode={copyMode}
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
