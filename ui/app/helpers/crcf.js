import cookie from 'cookie';

const crcf = () => {
  const cookies = cookie.parse(document.cookie);
  return ({
    headers: {
      'Content-Type': 'application/json',
      'X-CSRFToken': cookies.csrftoken,
    }
  })
};

export default crcf;
