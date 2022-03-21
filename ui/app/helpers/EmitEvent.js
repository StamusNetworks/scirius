const EmitEvent = (eventType) => {
  let evt;
  if (typeof Event === 'function') {
    // modern browsers
    evt = new Event(eventType);
  } else {
    // for IE and other old browsers
    // causes deprecation warning on modern browsers
    evt = window.document.createEvent('UIEvents');
    evt.initUIEvent(eventType, true, false, window, 0);
  }
  evt.huntEvent = true;
  window.dispatchEvent(evt);
};

export default EmitEvent;
