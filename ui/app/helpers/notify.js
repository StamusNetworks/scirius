import { notification } from 'antd';
import DOMPurify from 'dompurify';

const notify = (message, error, type = 'error') => {
  let description;

  (async () => {
    try {
      if (error.response) {
        description = `${error.response.status} ${error.response.statusText}\n`;
        const response = await error.response.text();
        description += DOMPurify.sanitize(response, { ALLOWED_TAGS: [] });
      } else if (error.message) {
        description = error.message;
      }
    } catch (e) {
      // do nothing
    }
  })();

  if (type === 'success') {
    notification.success({
      message,
      description,
      duration: 4.5,
    });
  } else {
    notification.error({
      message,
      duration: 4.5,
      description,
    });
  }
};

export default notify;
