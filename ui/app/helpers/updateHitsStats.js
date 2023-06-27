/* eslint-disable no-param-reassign */
import axios from 'axios';

import * as config from 'config/Api';
import { store } from 'ui/mobx/stores/RootStore';

function buildProbesSet(data) {
  const probes = [];
  for (let probe = 0; probe < data.length; probe += 1) {
    probes.push({ probe: data[probe].key, hits: data[probe].doc_count });
  }
  return probes;
}

function buildTimelineDataSet(tdata) {
  const timeline = { x: 'x', type: 'area', columns: [['x'], ['alerts']] };
  for (let key = 0; key < tdata.length; key += 1) {
    timeline.columns[0].push(tdata[key].key);
    timeline.columns[1].push(tdata[key].doc_count);
  }
  return timeline;
}

function processHitsStats(res, rules, updateCallback) {
  for (let rule = 0; rule < rules.length; rule += 1) {
    let found = false;
    for (let info = 0; info < res.data.length; info += 1) {
      if (res.data[info].key === rules[rule].sid) {
        rules[rule].timeline = buildTimelineDataSet(res.data[info].timeline.buckets);
        rules[rule].probes = buildProbesSet(res.data[info].probes.buckets);
        rules[rule].hits = res.data[info].doc_count;
        found = true;
        break;
      }
    }
    if (found === false) {
      rules[rule].hits = 0;
      rules[rule].probes = [];
      rules[rule].timeline = undefined;
    }
  }
  if (updateCallback) {
    updateCallback(rules);
  }
}

export async function updateHitsStats(rules, filterParams, updateCallback, qfilter) {
  const { stamus, alert, discovery } = store?.commonStore?.eventTypes || {};

  const sids = Array.from(rules, x => x.sid).join();
  const url = `${config.API_URL + config.ES_SIGS_LIST_PATH + sids}&${filterParams + qfilter}&alert=${alert}&stamus=${stamus}&discovery=${discovery}`;
  const res = await axios.get(url);
  processHitsStats(res, rules, updateCallback);
}
