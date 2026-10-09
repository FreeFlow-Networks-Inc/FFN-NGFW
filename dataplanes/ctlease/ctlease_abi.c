// SPDX-License-Identifier: GPL-2.0-or-later
#include <stdio.h>
#include "ffn_ctlease.h"
_Static_assert(sizeof(struct ffn_ctlease_bind)==72,"bind ABI");
_Static_assert(sizeof(struct ffn_ctlease_update)==48,"update ABI");
int main(void)
{
    printf("%lu %lu %lu\n",(unsigned long)FFN_CTLEASE_BIND,(unsigned long)FFN_CTLEASE_UPDATE,
           (unsigned long)FFN_CTLEASE_CHECK);
    return 0;
}
