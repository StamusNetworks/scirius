export const getCurrentUser = (param, fallback) => {
  const currentUser = window.current_user || {};
  if (param) {
    return currentUser[param] || fallback;
  }
  return currentUser;
};
