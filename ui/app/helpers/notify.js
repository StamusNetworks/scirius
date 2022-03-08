import { notification } from 'antd';
import DOMPurify from 'dompurify';

const notify = (message, error) => {
  let code;
  let response;

  try {
    (async () => {
      if (error.response) {
        response = await error.response.text().then(t => t);
        code = error.response.status;
      }
    })()
  } catch (e) {
    // do nothing
  }

  const description = (code && response) ? DOMPurify.sanitize(`[${code}] ${response}`, { ALLOWED_TAGS: [] }) : undefined;
  notification.error({
    message,
    duration: 4.5,
    description
  })
}

export default notify;
