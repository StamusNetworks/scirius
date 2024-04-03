import React, { useState } from 'react';

import { Button, Empty, Row } from 'antd';
import PropTypes from 'prop-types';

import { GeneralInformation, Buffer, Field } from './components';
import * as Styled from './styles';
import { getRuleData } from './utils';

export const Signature = ({ rule }) => {
  const [showSignatureText, setShowSignatureText] = useState(false);

  if (!rule.analysis) return <Styled.SigContent dangerouslySetInnerHTML={{ __html: rule.content_html }} key={rule.id} />;

  const { generalData, engines, metadata, references } = getRuleData(rule);

  return (
    <Styled.Wrapper>
      <Styled.Main>
        <GeneralInformation data={generalData} />
        <Styled.MainRight>
          <InfoBlock title="Metadata" data={metadata} />
          <InfoBlock title="References" data={references} span />
        </Styled.MainRight>
      </Styled.Main>
      <Styled.Row>
        {engines?.map(buffer => (
          <Buffer buffer={buffer} />
        ))}
      </Styled.Row>
      <Button onClick={() => setShowSignatureText(!showSignatureText)}>{showSignatureText ? 'Hide' : 'Show'} Signature Text</Button>
      {showSignatureText && <Styled.SigContent dangerouslySetInnerHTML={{ __html: rule.content_html }} key={rule.id} />}
    </Styled.Wrapper>
  );
};

Signature.propTypes = {
  rule: PropTypes.object,
};

const InfoBlock = ({ title, data, span = false }) => (
  <Styled.MainInfosCard flat={false} noPadding fullHeight flex>
    <Styled.Title>{title}</Styled.Title>
    {data?.length > 0 ? (
      <Styled.InfoRow span={span}>
        {data?.map(field => (
          <Field field={field} />
        ))}
      </Styled.InfoRow>
    ) : (
      <Row align="middle" justify="center" style={{ height: '100%' }}>
        <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} style={{ height: 'fit-content' }} />
      </Row>
    )}
  </Styled.MainInfosCard>
);

InfoBlock.propTypes = {
  title: PropTypes.string.isRequired,
  data: PropTypes.array.isRequired,
  span: PropTypes.bool,
};
