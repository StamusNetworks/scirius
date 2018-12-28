import React from 'react';
import PropTypes from 'prop-types';

const SourcePage = (props) => {
    const { source } = props;
    return (
        <h1>{source.name}</h1>
    );
}
SourcePage.propTypes = {
    source: PropTypes.any
};

export default SourcePage;
