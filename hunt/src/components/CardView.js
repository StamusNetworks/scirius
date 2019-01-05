import React from 'react';
import PropTypes from 'prop-types';

const CardView = (props) => <div className="container-fluid container-cards-pf">
    <div className="row row-cards-pf">{props.children}</div>
</div>;

CardView.propTypes = {
    children: PropTypes.any,
};

export default CardView;
