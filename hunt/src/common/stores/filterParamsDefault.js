const duration = localStorage.getItem('duration') || 24;

export const defaultFilterParams = {
    fromDate: Date.now() - (duration * 3600 * 1000)
};
