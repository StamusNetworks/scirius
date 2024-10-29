import { notification } from 'antd';
import DOMPurify from 'dompurify';

const notify = {
  error: (message, error = null) => {
    let description;

    (async () => {
      try {
        if (typeof error === 'string') {
          description = error;
        } else if (error.response) {
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

    notification.error({
      message,
      duration: 4.5,
      description,
    });
  },
  success: (message, description) => {
    notification.success({
      message,
      duration: 4.5,
      description,
    });
  },
};

export default notify;
