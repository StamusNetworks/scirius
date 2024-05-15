import React from 'react';

import PropTypes from 'prop-types';

import { getMarkdownText } from 'ui/helpers/markdown';

/* eslint-disable react/no-danger */
export const Markdown = ({ text }) => <div dangerouslySetInnerHTML={getMarkdownText(text)} />;

Markdown.propTypes = {
  text: PropTypes.string,
};
