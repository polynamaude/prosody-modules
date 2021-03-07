---
labels:
- 'Stage-Alpha'
summary: 'Store who created the invite to create a user account'
...

Introduction
============

Invites are an intermediate way between opening registrations completely and
closing registrations completely.

By letting users invite other users to the server, an administrator exposes
themselves again to the risk of abuse.

To combat that abuse more effectively, this module allows to store (outside
of the user’s information) who created an invite which was used to create the
user’s account.

Details
=======

Add to `modules_enabled`.

Caveats
=======

- The information is not deleted even when the associated user accounts are
  deleted.
- Currently, there is no way to make any use of that information.
