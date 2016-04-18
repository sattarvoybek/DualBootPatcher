/*
 * Copyright (C) 2014-2016  Andrew Gunnerson <andrewgunnerson@gmail.com>
 *
 * This file is part of MultiBootPatcher
 *
 * MultiBootPatcher is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * MultiBootPatcher is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with MultiBootPatcher.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include <string>

#include <sepol/policydb/policydb.h>

#define SELINUX_ENFORCE_FILE "/sys/fs/selinux/enforce"
#define SELINUX_POLICY_FILE "/sys/fs/selinux/policy"
#define SELINUX_LOAD_FILE "/sys/fs/selinux/load"

namespace mb
{
namespace util
{

bool selinux_mount();
bool selinux_unmount();
bool selinux_read_policy(const char *path, policydb_t *pdb);
bool selinux_write_policy(const char *path, policydb_t *pdb);
void selinux_make_all_permissive(policydb_t *pdb);
bool selinux_make_permissive(policydb_t *pdb, const char *type_str);
bool selinux_set_attribute(policydb_t *pdb, const char *type, int value);
bool selinux_create_type(policydb_t *pdb, const char *type_str);
bool selinux_add_rule(policydb_t *pdb,
                      const char *source_str,
                      const char *target_str,
                      const char *class_str,
                      const char *perm_str);
bool selinux_remove_rule(policydb_t *pdb,
                         const char *source_str,
                         const char *target_str,
                         const char *class_str,
                         const char *perm_str);
bool selinux_get_context(const char *path, std::string *context);
bool selinux_lget_context(const char *path, std::string *context);
bool selinux_fget_context(int fd, std::string *context);
bool selinux_set_context(const char *path, const char *context);
bool selinux_lset_context(const char *path, const char *context);
bool selinux_fset_context(int fd, const char *context);
bool selinux_set_context_recursive(const char *path, const char *context);
bool selinux_lset_context_recursive(const char *path, const char *context);
bool selinux_get_enforcing(int *value);
bool selinux_set_enforcing(int value);

}
}
