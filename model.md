# Domain model

A principal is a stable subject reference classified as human, agent, service, or
system. Kind is descriptive and grants no authority by itself.

A capability grant is issued by one Aegis engine under an authority epoch. It binds
a subject to a finite action set and resource scope until an explicit expiry. The
engine retains the minimum bounded facts required to validate currentness and
delegation ancestry.

Resource scopes use a versioned sum type for known engine boundaries rather than
uninterpreted permission strings. An extension requires a new vocabulary version or
an explicit adapter-owned foreign-resource profile.

Revocation affects future validation. Historical events continue to attribute the
grant and principal that authorized them at the time.

