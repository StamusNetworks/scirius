import React from 'react';
import PropTypes from 'prop-types';
import EventValue from 'ui/components/EventValue';

const DashboardBlockData = ({ block, data, copyMode }) => (
  <>
    {data?.map(item => (
      <EventValue
        key={item.key}
        field={block.i}
        value={item.key}
        right_info={<span className="badge">{item.doc_count}</span>}
        copyMode={copyMode}
        hasCopyShortcut
        format={block.format}
      />
    ))}
  </>
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
