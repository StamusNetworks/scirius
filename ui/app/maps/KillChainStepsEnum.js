import {
  actionsOnObjectivesColor,
  commandAndControlColor,
  deliveryColor,
  exploitationColor,
  installationColor,
  reconnaissanceColor,
  weaponizationColor,
} from 'styled-components-vars';

// Do not change order of key/value pairs as the Timeline Graph depends on it
export const KillChainStepsEnum = {
  reconnaissance: 'Reconnaissance',
  weaponization: 'Weaponization',
  delivery: 'Delivery',
  exploitation: 'Exploitation',
  installation: 'Installation',
  command_and_control: 'Command and Control',
  actions_on_objectives: 'Actions on Objectives',
};

export const KillChainColors = {
  reconnaissance: reconnaissanceColor,
  weaponization: weaponizationColor,
  delivery: deliveryColor,
  exploitation: exploitationColor,
  installation: installationColor,
  command_and_control: commandAndControlColor,
  actions_on_objectives: actionsOnObjectivesColor,
};

export const KillChainToColorMap = {
  Reconnaissance: reconnaissanceColor,
  Weaponization: weaponizationColor,
  Delivery: deliveryColor,
  Exploitation: exploitationColor,
  Installation: installationColor,
  'Command and Control': commandAndControlColor,
  'Actions on Objectives': actionsOnObjectivesColor,
};
