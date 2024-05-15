import React from 'react';

import PropTypes from 'prop-types';

import { Markdown } from 'ui/components/Markdown';
import UICard from 'ui/components/UIElements/UICard';

import * as Style from './style';

export const AlgorithmicDetection = ({ rule }) => (
  <div>
    {rule.method.description && <p>{rule.method.description}</p>}
    <Style.Row>
      {rule.threat_info.threat__description && (
        <UICard title="Description">
          <Markdown text={rule.threat_info.threat__description} />
        </UICard>
      )}
      {rule.threat_info.threat__additional_info && (
        <UICard title="Additional Info">
          <Markdown text={rule.threat_info.threat__additional_info} />
        </UICard>
      )}
    </Style.Row>
  </div>
);

AlgorithmicDetection.propTypes = {
  rule: PropTypes.shape({
    method: PropTypes.shape({
      description: PropTypes.string,
    }),
    threat_info: PropTypes.shape({
      threat__description: PropTypes.string,
      threat__additional_info: PropTypes.string,
      threat__name: PropTypes.string,
    }),
  }).isRequired,
};
