export const formatValidationError = errors => {
  if (!errors || !errors.issues) return 'Validation failed';

  // if its an array where the issue came from possibility [user, admin] roles
  if (Array.isArray(errors.issues))
    return errors.issues.map(i => i.message).join(', ');

  return JSON.stringify(errors);
};
