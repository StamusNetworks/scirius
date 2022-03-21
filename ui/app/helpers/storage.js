import { sections } from 'hunt_common/constants';

const params = new URLSearchParams(window.location.search);

const getType = () => (params.has('session') && params.get('session') === 'temporary' ? 'temporary' : 'normal');

const storage = getType() === 'temporary' ? sessionStorage : localStorage;

const setPage = (page) => {
  storage.setItem('page_display', JSON.stringify({ page }));
};

const setFilter = (key, value) => {
  storage.setItem(key, JSON.stringify(value));
};

const isInit = () => {
  let result = storage.getItem('init') || 'false';
  try {
    result = JSON.parse(result);
  } catch (e) {
    result = false;
  }
  return result;
};
if (getType() === 'temporary' && !isInit()) {
  setPage(params.get('page'));
  const ip = params.get('ip');
  const tenantId = params.get('tenant');
  if (ip) {
    let existingFilters = storage.getItem(sections.GLOBAL) || '[]';
    try {
      existingFilters = JSON.parse(existingFilters);
      existingFilters = existingFilters.filter((o) => o.id !== 'host_id.ip');
      setFilter(sections.GLOBAL, [{ id: 'host_id.ip', value: ip, negated: false }, ...existingFilters]);
    } catch (e) {
      setFilter(sections.GLOBAL, []);
    }
  }
  if (tenantId) {
    storage.setItem('filterParams.tenant', tenantId);
  }
  storage.setItem('init', 'true');
}

export default storage;
