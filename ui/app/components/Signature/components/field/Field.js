import React from 'react';

import PropTypes from 'prop-types';

import * as Signature from '../../styles';
import { getEngineTagColor } from '../../utils';

export const Field = ({ field }) => (
  <Signature.Field>
    <Signature.LabelRow>
      <Signature.Label>{field.label}</Signature.Label>
      <Signature.Tags>
        {field?.tags?.map(tag => (
          <Signature.Tag color={getEngineTagColor(tag)}>{tag}</Signature.Tag>
        ))}
      </Signature.Tags>
    </Signature.LabelRow>
    {getField(field)}
  </Signature.Field>
);
Field.propTypes = {
  field: PropTypes.object.isRequired,
};

const getField = field => {
  switch (field.label.toLowerCase()) {
    case 'url':
      return (
        <Signature.ValueAsLink href={`https://${field.value}`} target="_blank">
          {field.value}
        </Signature.ValueAsLink>
      );
    case 'md5':
      return (
        <Signature.ValueAsLink href={`https://www.google.com/search?q=${field.value}`} target="_blank" title="Search on google">
          {field.value}
        </Signature.ValueAsLink>
      );
    default:
      return <Signature.Value>{field.value}</Signature.Value>;
  }
};
