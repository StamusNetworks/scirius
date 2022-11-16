import React, { useEffect } from 'react';
import { UploadOutlined, LoadingOutlined } from '@ant-design/icons';
import { Button, message } from 'antd';
import actions from 'ui/containers/App/actions';
import selectors from 'ui/containers/App/selectors';
import { useDispatch, useSelector } from 'react-redux';

const UpdatePushRuleset = () => {
  const dispatch = useDispatch();
  const { request } = useSelector(selectors.makeSelectUpdatePushRuleset());
  const { loading = false, status } = request;
  useEffect(() => {
    if (!loading && status) {
      message.success({ content: 'Successfully updated / pushed ruleset' });
    }
  }, [loading, status]);

  return (
    <Button
      size="small"
      type="primary"
      disabled={loading}
      icon={loading ? <LoadingOutlined /> : <UploadOutlined />}
      onClick={() => dispatch(actions.updatePushRulesetRequest())}
    >
      Update / Push ruleset
    </Button>
  );
};

export default UpdatePushRuleset;
