const map = type => {
  switch (type) {
    case ':dates': {
      return {
        start_date: localStorage.getItem('startDate'),
        end_date: localStorage.getItem('endDate'),
      };
    }
    // should be used for all `/es/*` requests
    case ':datesEs': {
      return {
        from_date: localStorage.getItem('startDate') * 1000,
        to_date: localStorage.getItem('endDate') * 1000,
      };
    }
    case ':eventTypes': {
      return {
        alert: JSON.parse(localStorage.getItem('alert_tag'))?.value?.alerts,
        discovery: !!JSON.parse(localStorage.getItem('alert_tag'))?.value?.sightings,
        stamus: JSON.parse(localStorage.getItem('alert_tag'))?.value?.stamus,
      };
    }
    default:
      return {};
  }
};

export default map;
