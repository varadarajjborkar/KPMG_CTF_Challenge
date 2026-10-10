note to self (M. Reyes, infra) --

pulled these 300 candidate keys per the audit request, never got
around to confirming which one is actually live myself. if you're
reading this because you already matched one of them against the
deployed authorized_keys -- good, you're further along than I got.
(for the record since it's easy to lose track of: the account on the
other end of that authorized_keys file is svc-legacydb -- that's who
the matched key logs in as.)

there's also a leftover account-data backup I found sitting in the
same cold-storage box, never cleaned up:

    /archive/backups/e6f25638ae2ed6ba955cdae6a74c6798.zip

it's password-protected (don't ask me why, ops insisted on it after
the last audit). whoever set it up left a note that the password is
"right there in the real key once you've found it" -- specifically:
the password is the BODY of the matching .pem file -- not the full
file, not the header/footer lines, just the base64 block in between.
take whichever one of these .pem files is the actual match, strip the
"-----BEGIN...-----" and "-----END...-----" lines and every line break
from what's left, and take the first 64 characters of THAT. that's it,
no further trick.

-- M.R.
