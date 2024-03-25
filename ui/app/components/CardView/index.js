import React from 'react';

import PropTypes from 'prop-types';

const CardView = props => (
  <div className="container-fluid container-cards-pf">
    <div className="row row-cards-pf">{props.dataSource.map(props.renderItem)}</div>
  </div>
);

CardView.propTypes = {
  dataSource: PropTypes.arrayOf(PropTypes.object),
  renderItem: PropTypes.func,
};

export default CardView;
