No deployment has this epoch. A deployment is named by its configuration epoch, which `kronik deploy` and `kronik promote` print; a rollback names the deployment to undo this way.

Typical causes: a typo, or an epoch that belongs to another configuration change, such as a grant or a limits change, and not to a deployment.

    kronik deployments list

See also: `deployment`, `configuration-epoch`, `ROLLBACK_SCHEMA_CHANGED`.
