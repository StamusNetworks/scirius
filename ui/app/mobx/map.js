const map = type => {
  switch (type) {
    case ':dates': {
      return {
        from_date: localStorage.getItem('startDate'),
        to_date: localStorage.getItem('startDate'),
      };
    }
    case ':datesEs': {
      return {
        from_date: localStorage.getItem('startDate') * 1000,
        to_date: localStorage.getItem('endDate') * 1000,
      };
    }
    default:
      return {};
  }
};

export default map;
