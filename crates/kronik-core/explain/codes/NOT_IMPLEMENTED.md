The requested operation is not implemented by this version. This is not the error for microVM admission: its missing-KVM and missing-tool failures use KVM_UNAVAILABLE and FOREIGN_UNAVAILABLE.

Check the command's supported operations and `kronik --version`; an unavailable feature must not be replaced silently by a weaker isolation or different operation:

    kronik --version

See also: `isolation-level`.
