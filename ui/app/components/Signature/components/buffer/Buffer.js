import React from 'react';

import PropTypes from 'prop-types';

import * as SignatureStyle from '../../styles';
import { Field } from '../field';
import * as Style from './styles';

export const Buffer = ({ buffer }) => (
  <SignatureStyle.Card flat={false} noPadding>
    <Style.Row>
      <SignatureStyle.Title>{buffer.name}</SignatureStyle.Title>
      {buffer.transforms?.length > 0 && (
        <SignatureStyle.Tags>
          {buffer.transforms?.map(tag => (
            <SignatureStyle.Tag color="yellow">{tag}</SignatureStyle.Tag>
          ))}
        </SignatureStyle.Tags>
      )}
    </Style.Row>
    <Style.Matches>
      {buffer.matches?.map(match => (
        <Field field={match} />
      ))}
    </Style.Matches>
  </SignatureStyle.Card>
);

Buffer.propTypes = {
  buffer: PropTypes.object.isRequired,
};
