import {
  actionsOnObjectivesColor,
  commandAndControlColor,
  deliveryColor,
  exploitationColor,
  installationColor,
  reconnaissanceColor,
  weaponizationColor,
  policyViolationColor,
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
  pre_condition: 'Policy Violation',
};

export const KillChainStepsEnumFromInt = {
  0: 'Reconnaissance',
  1: 'Weaponization',
  2: 'Delivery',
  3: 'Exploitation',
  4: 'Installation',
  5: 'Command and Control',
  6: 'Actions on Objectives',
};

export const KillChainColors = {
  reconnaissance: reconnaissanceColor,
  weaponization: weaponizationColor,
  delivery: deliveryColor,
  exploitation: exploitationColor,
  installation: installationColor,
  command_and_control: commandAndControlColor,
  actions_on_objectives: actionsOnObjectivesColor,
  pre_condition: policyViolationColor,
};

export const KillChainToColorMap = {
  Reconnaissance: reconnaissanceColor,
  Weaponization: weaponizationColor,
  Delivery: deliveryColor,
  Exploitation: exploitationColor,
  Installation: installationColor,
  'Command and Control': commandAndControlColor,
  'Actions on Objectives': actionsOnObjectivesColor,
  'Policy Violation': policyViolationColor,
};

export const KillChainToInt = {
  reconnaissance: 1,
  weaponization: 2,
  delivery: 3,
  exploitation: 4,
  installation: 5,
  command_and_control: 6,
  actions_on_objectives: 7,
  policy_violation: -1,
};

export const KillChainFromInt = {
  1: 'reconnaissance',
  2: 'weaponization',
  3: 'delivery',
  4: 'exploitation',
  5: 'installation',
  6: 'command_and_control',
  7: 'actions_on_objectives',
  '-1': 'policy_violation',
};
