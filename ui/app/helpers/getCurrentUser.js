export const getCurrentUser = (param, fallback) => {
  const currentUser = window.current_user || {};
  if (param) {
    if (typeof fallback !== 'undefined') {
      return currentUser[param] || fallback;
    }
    return currentUser ? currentUser[param] : fallback;
  }
  return currentUser;
};
