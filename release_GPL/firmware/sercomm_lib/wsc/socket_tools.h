/* =============================================================================      
 * Copyright (C) 2006-2007, Sercomm (Suzhou) R&D Center,  All Rights Reserved
 * =============================================================================
 */

#ifndef _SOCKETTOOLS_H_
#define _SOCKETTOOLS_H_

#include "nvram.h"

#define scfgmgr_commit() { nvram_commit(); }

#define scfgmgr_set(name, data) { nvram_set(name, data); }

#define scfgmgr_get(name, value) { value = nvram_get(name); }

#endif /* _SOCKETTOOLS_H_ */
