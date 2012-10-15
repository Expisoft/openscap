/*
 * Copyright 2012 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */

#ifndef OSCAP_ACQUIRE_H_
#define OSCAP_ACQUIRE_H_

#include <stdbool.h>

/**
 * Create an oscap temp dir. (While ideally all the operations are being
 * made on unliked files using file descriptors, this is bordeline impossible
 * in short term given the library interfaces.
 * This function emits a message on stderr in case of error.
 * @return filename of the temporary directory or NULL on error.
 */
char *oscap_acquire_temp_dir(void);

/**
 * Download the given url to a random file in the given directory.
 * @param temp_dir Directory to store the result in.
 * @param url The url to acquire.
 * @return the filename of the newly created file or NULL on error.
 */
char *oscap_acquire_url_download(const char *temp_dir, const char *url);

/**
 * Is the given url supported by OpenSCAP?
 * @param url Requested url
 * @return true if the given string reminds supported url.
 */
bool oscap_acquire_url_is_supported(const char *url);

#endif