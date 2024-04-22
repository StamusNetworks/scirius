import React from 'react';

import { Button, Empty } from 'antd';
import { useHistory } from 'react-router-dom';

import { APP_URL } from 'ui/config';
import OperationalCenter from 'ui/pages/OperationalCenter/OperationalCenter';

import * as Style from './style';

const NotFound = () => (
  <Style.PageWrapper>
    <Empty description={<Description />} />
  </Style.PageWrapper>
);

const Description = () => {
  const history = useHistory();
  return (
    <div>
      <h2>Not found</h2>
      <p>The page you are trying to access is either missing or contains no data.</p>
      <Button
        type="primary"
        onClick={() => history.push({ pathname: `${APP_URL}/${OperationalCenter.metadata.url}`, search: history.location.search })}
      >
        Take me home
      </Button>
    </div>
  );
};

NotFound.metadata = {
  url: '',
};

export default NotFound;
