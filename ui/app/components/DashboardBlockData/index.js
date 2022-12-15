import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';
import { CSSTransition, TransitionGroup } from 'react-transition-group';

const DashboardBlockData = ({ block, data, copyMode }) => (
  <TransitionGroup>
    {data?.map(item => (
      <CSSTransition key={item.key} nodeRef={item.nodeRef} timeout={500} classNames="item">
        <EventValue
          ref={item.nodeRef}
          key={item.key}
          field={block.i}
          value={item.key}
          right_info={<span className="badge">{item.doc_count}</span>}
          copyMode={copyMode}
          hasCopyShortcut
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
    dimensions: PropTypes.shape({
      xxl: PropTypes.number,
      xl: PropTypes.number,
    }),
  }),
  data: PropTypes.array.isRequired,
  copyMode: PropTypes.bool.isRequired,
};
