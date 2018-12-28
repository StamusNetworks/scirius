import React from 'react';
import PropTypes from 'prop-types';

const RuleSetPage = (props) => {
    const { ruleset } = props;
    return (
        <h1>{ruleset.name}</h1>
    );
}

RuleSetPage.propTypes = {
    ruleset: PropTypes.any
};

export default RuleSetPage;
