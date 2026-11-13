# SECRET_EXTERNAL

This name is linked to an external secret manager. Kronik does not write or delete values in that service.

Change or rotate the value using the backend's own authorized tools, then run `kronik secret refresh <name> --reason '...'`. To return future turns to the built-in store, an administrator can explicitly unlink the name. Unlinking does not redirect historical versions or make an old recorded value equal to the current one.

A foreign actor gets a linked name through the node's secret cache, and a fork uses the value the node holds for the fork point's link; neither answers with this code. Releases before 0.5.0 refused a linked name there with it.
