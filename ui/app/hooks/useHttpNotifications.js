import React, { useEffect } from 'react';
import { notification } from 'antd';
import DOMPurify from 'dompurify';
import { usePrevious } from './usePrevious';

export const useHttpNotifications = ({ request, notifyFailures = false, notifySuccesses = false, duration = 4.5 }) => {
  const [api, contextHolder] = notification.useNotification();
  const prevLoading = usePrevious(request.loading);
  const { message = '' } = request;

  const cleanMessage = DOMPurify.sanitize(message, { ALLOWED_TAGS: [] });
  useEffect(() => {
    if (notifySuccesses && request.status === true && prevLoading && !request.loading) {
      api.success({
        message: `Success`,
        description: cleanMessage,
        placement: 'topRight',
        duration,
      });
    } else if (notifyFailures && request.status === false && prevLoading && !request.loading) {
      api.error({
        message: `Failure`,
        description: cleanMessage.split('\n').map(row => <div>{row}</div>),
        placement: 'topRight',
        duration,
      });
    }
  });
  return contextHolder;
};
