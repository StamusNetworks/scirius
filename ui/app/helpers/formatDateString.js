import moment from 'moment';
import { DATE_TIME_FORMAT } from 'ui/constants';

export const formatDateString = str => moment(str).format(DATE_TIME_FORMAT);
