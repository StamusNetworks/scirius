import React from 'react';

import { Button, Empty } from 'antd';
import { useHistory } from 'react-router-dom';

import { HOME_PATH } from 'ui/config';

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
      <Button type="primary" onClick={() => history.push({ pathname: HOME_PATH, search: history.location.search })}>
        Take me home
      </Button>
    </div>
  );
};

NotFound.metadata = {
  url: '',
};

export default NotFound;
