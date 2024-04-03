import React from 'react';

import PropTypes from 'prop-types';

import * as Signature from '../../styles';
import { Field } from '../field';
import { Target } from '../target';
import * as Styled from './styles';

export const GeneralInformation = ({ data }) => {
  const { originIp, originPort, destinationIp, destinationPort, protocol, destination, target, rev, classtype } = data;

  return (
    <Signature.MainInfosCard flat={false} noPadding>
      <Signature.Title>General Information</Signature.Title>
      <Target destination={destination} target={target} />
      <Styled.TopRow>
        <div>
          <Field field={originIp} />
          <Field field={originPort} />
        </div>
        <div>
          <Styled.VerticalDivider />
        </div>
        <div>
          <Field field={destinationIp} />
          <Field field={destinationPort} />
        </div>
      </Styled.TopRow>
      <Signature.Divider />
      <Styled.Row span>
        <Field field={classtype} />
      </Styled.Row>
      <Styled.Row>
        <Field field={protocol} />
        <Field field={rev} />
      </Styled.Row>
    </Signature.MainInfosCard>
  );
};

GeneralInformation.propTypes = {
  data: PropTypes.object.isRequired,
};
