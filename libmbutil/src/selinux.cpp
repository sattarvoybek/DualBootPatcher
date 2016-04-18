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

#include "mbutil/selinux.h"

#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wkeyword-macro"
#define bool bool_
#include <sepol/policydb/expand.h>
#undef bool
#pragma GCC diagnostic pop

#include <sepol/sepol.h>

#include "mblog/logging.h"
#include "mbutil/finally.h"
#include "mbutil/fts.h"
#include "mbutil/mount.h"

#define SELINUX_MOUNT_POINT     "/sys/fs/selinux"
#define SELINUX_FS_TYPE         "selinuxfs"

#define SELINUX_XATTR           "security.selinux"

#define DEFAULT_SEPOLICY_FILE   "/sepolicy"

#define OPEN_ATTEMPTS           5


namespace mb
{
namespace util
{

class RecursiveSetContext : public FTSWrapper {
public:
    RecursiveSetContext(std::string path, std::string context,
                        bool follow_symlinks)
        : FTSWrapper(path, FTS_GroupSpecialFiles),
        _context(std::move(context)),
        _follow_symlinks(follow_symlinks)
    {
    }

    virtual int on_reached_directory_post() override
    {
        return set_context() ? Action::FTS_OK : Action::FTS_Fail;
    }

    virtual int on_reached_file() override
    {
        return set_context() ? Action::FTS_OK : Action::FTS_Fail;
    }

    virtual int on_reached_symlink() override
    {
        return set_context() ? Action::FTS_OK : Action::FTS_Fail;
    }

    virtual int on_reached_special_file() override
    {
        return set_context() ? Action::FTS_OK : Action::FTS_Fail;
    }

private:
    std::string _context;
    bool _follow_symlinks;

    bool set_context()
    {
        if (_follow_symlinks) {
            return selinux_set_context(_curr->fts_accpath, _context.c_str());
        } else {
            return selinux_lset_context(_curr->fts_accpath, _context.c_str());
        }
    }
};

bool selinux_mount()
{
    // Try /sys/fs/selinux
    if (!util::mount(SELINUX_FS_TYPE, SELINUX_MOUNT_POINT,
                     SELINUX_FS_TYPE, 0, nullptr)) {
        LOGW("Failed to mount %s at %s: %s",
             SELINUX_FS_TYPE, SELINUX_MOUNT_POINT, strerror(errno));
        if (errno == ENODEV || errno == ENOENT) {
            LOGI("Kernel does not support SELinux");
        }
        return false;
    }

    // Load default policy
    struct stat sb;
    if (stat(DEFAULT_SEPOLICY_FILE, &sb) == 0) {
        policydb_t pdb;

        if (policydb_init(&pdb) < 0) {
            LOGE("Failed to initialize policydb");
            return false;
        }

        if (!selinux_read_policy(DEFAULT_SEPOLICY_FILE, &pdb)) {
            LOGE("Failed to read SELinux policy file: %s",
                 DEFAULT_SEPOLICY_FILE);
            policydb_destroy(&pdb);
            return false;
        }

        // Make all types permissive. Otherwise, some more restrictive policies
        // will prevent the real init from loading /sepolicy because init
        // (stage 1) runs under the `u:r:kernel:s0` context.
        util::selinux_make_all_permissive(&pdb);

        if (!selinux_write_policy(SELINUX_LOAD_FILE, &pdb)) {
            LOGE("Failed to write SELinux policy file: %s",
                 SELINUX_LOAD_FILE);
            policydb_destroy(&pdb);
            return false;
        }

        policydb_destroy(&pdb);

        return true;
    }

    return true;
}

bool selinux_unmount()
{
    if (!util::is_mounted(SELINUX_MOUNT_POINT)) {
        LOGI("No SELinux filesystem to unmount");
        return false;
    }

    if (!util::umount(SELINUX_MOUNT_POINT)) {
        LOGE("Failed to unmount %s: %s", SELINUX_MOUNT_POINT, strerror(errno));
        return false;
    }

    return true;
}

bool selinux_read_policy(const char *path, policydb_t *pdb)
{
    struct policy_file pf;
    struct stat sb;
    void *map;
    int fd;

    for (int i = 0; i < OPEN_ATTEMPTS; ++i) {
        fd = open(path, O_RDONLY);
        if (fd < 0) {
            LOGE("[%d/%d] %s: Failed to open sepolicy: %s",
                 i + 1, OPEN_ATTEMPTS, path, strerror(errno));
            if (errno == EBUSY) {
                usleep(500 * 1000);
                continue;
            } else {
                return false;
            }
        }
        break;
    }

    auto close_fd = finally([&] {
        close(fd);
    });

    if (fstat(fd, &sb) < 0) {
        LOGE("%s: Failed to stat sepolicy: %s", path, strerror(errno));
        return false;
    }

    map = mmap(nullptr, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (map == MAP_FAILED) {
        LOGE("%s: Failed to mmap sepolicy: %s", path, strerror(errno));
        return false;
    }

    auto unmap_map = finally([&] {
        munmap(map, sb.st_size);
    });

    policy_file_init(&pf);
    pf.type = PF_USE_MEMORY;
    pf.data = (char *) map;
    pf.len = sb.st_size;

    auto destroy_pf = finally([&] {
        sepol_handle_destroy(pf.handle);
    });

    return policydb_read(pdb, &pf, 0) == 0;
}

// /sys/fs/selinux/load requires the entire policy to be written in a single
// write(2) call.
// See: http://marc.info/?l=selinux&m=141882521027239&w=2
bool selinux_write_policy(const char *path, policydb_t *pdb)
{
    void *data;
    size_t len;
    sepol_handle_t *handle;
    int fd;

    // Don't print warnings to stderr
    handle = sepol_handle_create();
    sepol_msg_set_callback(handle, nullptr, nullptr);

    auto destroy_handle = finally([&] {
        sepol_handle_destroy(handle);
    });

    if (policydb_to_image(handle, pdb, &data, &len) < 0) {
        LOGE("Failed to write policydb to memory");
        return false;
    }

    auto free_data = finally([&] {
        free(data);
    });

    for (int i = 0; i < OPEN_ATTEMPTS; ++i) {
        fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
        if (fd < 0) {
            LOGE("[%d/%d] %s: Failed to open sepolicy: %s",
                 i + 1, OPEN_ATTEMPTS, path, strerror(errno));
            if (errno == EBUSY) {
                usleep(500 * 1000);
                continue;
            } else {
                return false;
            }
        }
        break;
    }

    auto close_fd = finally([&] {
        close(fd);
    });

    if (write(fd, data, len) < 0) {
        LOGE("%s: Failed to write sepolicy: %s", path, strerror(errno));
        return false;
    }

    return true;
}

void selinux_make_all_permissive(policydb_t *pdb)
{
    //char *name;

    for (unsigned int i = 0; i < pdb->p_types.nprim - 1; i++) {
        //name = pdb->p_type_val_to_name[i];
        //if (ebitmap_get_bit(&pdb->permissive_map, i + 1)) {
        //    LOGD("Type %s is already permissive", name);
        //} else {
            ebitmap_set_bit(&pdb->permissive_map, i + 1, 1);
        //    LOGD("Made %s permissive", name);
        //}
    }
}

bool selinux_make_permissive(policydb_t *pdb, const char *type_str)
{
    type_datum_t *type;

    type = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) type_str);
    if (!type) {
        LOGV("Type %s not found in policy", type_str);
        return false;
    }

    if (ebitmap_get_bit(&pdb->permissive_map, type->s.value)) {
        LOGV("Type %s is already permissive", type_str);
        return true;
    }

    if (ebitmap_set_bit(&pdb->permissive_map, type->s.value, 1) < 0) {
        LOGE("Failed to set bit for type %s in the permissive map", type_str);
        return false;
    }

    LOGD("Type %s is now permissive", type_str);

    return true;
}

// Based on public domain code from an sepolicy-inject fork:
// https://github.com/phhusson/sepolicy-inject/blob/master/sepolicy-inject.c
bool selinux_set_attribute(policydb_t *pdb, const char *type, int value)
{
    type_datum_t *attr = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) type);
    if (!attr) {
        return false;
    }

    if (attr->flavor != TYPE_ATTRIB) {
        return false;
    }

    if (ebitmap_set_bit(
            &pdb->type_attr_map[value - 1], attr->s.value - 1, 1) < 0) {
        return false;
    }
    if (ebitmap_set_bit(
            &pdb->attr_type_map[attr->s.value - 1], value - 1, 1) < 0) {
        return false;
    }

    return true;
}

extern "C" int policydb_index_decls(policydb_t * p);

// Based on public domain code from an sepolicy-inject fork:
// https://github.com/phhusson/sepolicy-inject/blob/master/sepolicy-inject.c
bool selinux_create_type(policydb_t *pdb, const char *type_str)
{
    type_datum_t *type = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) type_str);
    if (type) {
        return true;
    }

    type = (type_datum_t *) malloc(sizeof(type_datum_t));
    char *type_str_dup = strdup(type_str);

    if (!type || !type_str_dup) {
        free(type);
        free(type_str_dup);
        return false;
    }

    type_datum_init(type);
    type->primary = 1;
    type->flavor = TYPE_TYPE;

    uint32_t value = 0;
    int ret = symtab_insert(
            pdb, SYM_TYPES, type_str_dup, type, SCOPE_DECL, 1, &value);
    if (ret != 0) {
        free(type);
        free(type_str_dup);
        return false;
    }

    type->s.value = value;

    if (ebitmap_set_bit(&pdb->global->branch_list->declared.scope[SYM_TYPES],
                        value - 1, 1) < 0) {
        return false;
    }

    ebitmap_t *type_attr_map = (ebitmap_t *) realloc(
            pdb->type_attr_map, sizeof(ebitmap_t) * pdb->p_types.nprim);
    ebitmap_t *attr_type_map = (ebitmap_t *) realloc(
            pdb->attr_type_map, sizeof(ebitmap_t) * pdb->p_types.nprim);

    if (!type_attr_map || !attr_type_map) {
        if (type_attr_map) {
            pdb->type_attr_map = type_attr_map;
        }
        if (attr_type_map) {
            pdb->attr_type_map = attr_type_map;
        }
        return false;
    }

    pdb->type_attr_map = type_attr_map;
    pdb->attr_type_map = attr_type_map;
    ebitmap_init(&pdb->type_attr_map[value - 1]);
    ebitmap_init(&pdb->attr_type_map[value - 1]);

    if (ebitmap_set_bit(&pdb->type_attr_map[value - 1], value - 1, 1) < 0) {
        return false;
    }

    // Add the domain to all roles
    for (uint32_t i = 0; i < pdb->p_roles.nprim; ++i) {
        bool ret = ebitmap_set_bit(&pdb->role_val_to_struct[i]->types.negset, value - 1, 0) == 0
                && ebitmap_set_bit(&pdb->role_val_to_struct[i]->types.types, value - 1, 1) == 0
                && type_set_expand(&pdb->role_val_to_struct[i]->types, &pdb->role_val_to_struct[i]->cache, pdb, 0) == 0;
        if (!ret) {
            return false;
        }
    }

    type = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) type_str);
    if (!type) {
        return false;
    }

    if (policydb_index_decls(pdb) < 0) {
        return false;
    }

    if (policydb_index_classes(pdb) < 0) {
        return false;
    }

    if (policydb_index_others(nullptr, pdb, 1) < 0) {
        return false;
    }

    return true;
}

// Based on public domain code from sepolicy-inject:
// https://bitbucket.org/joshua_brindle/sepolicy-inject/
// See the following commit about the hashtab_key_t casts:
// https://github.com/TresysTechnology/setools/commit/2994d1ca1da9e6f25f082c0dd1a49b5f958bd2ca
static bool selinux_add_or_remove_rule(policydb_t *pdb,
                                       const char *source_str,
                                       const char *target_str,
                                       const char *class_str,
                                       const char *perm_str,
                                       bool remove)
{
    type_datum_t *source, *target;
    class_datum_t *clazz;
    perm_datum_t *perm;
    avtab_datum_t *av;
    avtab_key_t key;

    source = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) source_str);
    if (!source) {
        LOGE("Source type %s does not exist", source_str);
        return false;
    }
    target = (type_datum_t *) hashtab_search(
            pdb->p_types.table, (hashtab_key_t) target_str);
    if (!target) {
        LOGE("Target type %s does not exist", target_str);
        return false;
    }
    clazz = (class_datum_t *) hashtab_search(
            pdb->p_classes.table, (hashtab_key_t) class_str);
    if (!clazz) {
        LOGE("Class %s does not exist", class_str);
        return false;
    }
    perm = (perm_datum_t *) hashtab_search(
            clazz->permissions.table, (hashtab_key_t) perm_str);
    if (!perm) {
        if (clazz->comdatum == nullptr) {
            LOGE("Perm %s does not exist in class %s", perm_str, class_str);
            return false;
        }
        perm = (perm_datum_t *) hashtab_search(
                clazz->comdatum->permissions.table, (hashtab_key_t) perm_str);
        if (!perm) {
            LOGE("Perm %s does not exist in class %s", perm_str, class_str);
            return false;
        }
    }

    // See if there is already a rule
    key.source_type = source->s.value;
    key.target_type = target->s.value;
    key.target_class = clazz->s.value;
    key.specified = AVTAB_ALLOWED;
    av = avtab_search(&pdb->te_avtab, &key);

    if (!av) {
        avtab_datum_t av_new;
        av_new.data = (1U << (perm->s.value - 1));
        if (avtab_insert(&pdb->te_avtab, &key, &av_new) != 0) {
            LOGE("Failed to add rule to avtab");
            return false;
        }
    } else {
        const char *msg;
        if (remove) {
            if (av->data & (1U << (perm->s.value - 1))) {
                msg = "Removed rule";
            } else {
                msg = "Rule does not exist";
            }
            av->data &= ~(1U << (perm->s.value - 1));
        } else {
            if (av->data & (1U << (perm->s.value - 1))) {
                msg = "Rule already exists";
            } else {
                msg = "Added rule";
            }
            av->data |= (1U << (perm->s.value - 1));
        }
        LOGD("%s: \"allow %s %s:%s %s;\"",
             msg, source_str, target_str, class_str, perm_str);
    }

    return true;
}

bool selinux_add_rule(policydb_t *pdb,
                      const char *source_str,
                      const char *target_str,
                      const char *class_str,
                      const char *perm_str)
{
    return selinux_add_or_remove_rule(pdb, source_str, target_str, class_str,
                                      perm_str, false);
}

bool selinux_remove_rule(policydb_t *pdb,
                         const char *source_str,
                         const char *target_str,
                         const char *class_str,
                         const char *perm_str)
{
    return selinux_add_or_remove_rule(pdb, source_str, target_str, class_str,
                                      perm_str, true);
}

bool selinux_get_context(const char *path, std::string *context)
{
    ssize_t size;
    std::vector<char> value;

    size = getxattr(path, SELINUX_XATTR, nullptr, 0);
    if (size < 0) {
        return false;
    }

    value.resize(size);

    size = getxattr(path, SELINUX_XATTR, value.data(), size);
    if (size < 0) {
        return false;
    }

    value.push_back('\0');
    *context = value.data();

    return true;
}

bool selinux_lget_context(const char *path, std::string *context)
{
    ssize_t size;
    std::vector<char> value;

    size = lgetxattr(path, SELINUX_XATTR, nullptr, 0);
    if (size < 0) {
        return false;
    }

    value.resize(size);

    size = lgetxattr(path, SELINUX_XATTR, value.data(), size);
    if (size < 0) {
        return false;
    }

    value.push_back('\0');
    *context = value.data();

    return true;
}

bool selinux_fget_context(int fd, std::string *context)
{
    ssize_t size;
    std::vector<char> value;

    size = fgetxattr(fd, SELINUX_XATTR, nullptr, 0);
    if (size < 0) {
        return false;
    }

    value.resize(size);

    size = fgetxattr(fd, SELINUX_XATTR, value.data(), size);
    if (size < 0) {
        return false;
    }

    value.push_back('\0');
    *context = value.data();

    return true;
}

bool selinux_set_context(const char *path, const char *context)
{
    return setxattr(path, SELINUX_XATTR,
                    context, strlen(context) + 1, 0) == 0;
}

bool selinux_lset_context(const char *path, const char *context)
{
    return lsetxattr(path, SELINUX_XATTR,
                     context, strlen(context) + 1, 0) == 0;
}

bool selinux_fset_context(int fd, const char *context)
{
    return fsetxattr(fd, SELINUX_XATTR,
                     context, strlen(context) + 1, 0) == 0;
}

bool selinux_set_context_recursive(const char *path,
                                   const char *context)
{
    return RecursiveSetContext(path, context, true).run();
}

bool selinux_lset_context_recursive(const char *path,
                                    const char *context)
{
    return RecursiveSetContext(path, context, false).run();
}

bool selinux_get_enforcing(int *value)
{
    int fd = open(SELINUX_ENFORCE_FILE, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    char buf[20];
    memset(buf, 0, sizeof(buf));
    int ret = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (ret < 0) {
        return false;
    }

    int enforce = 0;
    if (sscanf(buf, "%d", &enforce) != 1) {
        return false;
    }

    *value = enforce;

    return true;
}

bool selinux_set_enforcing(int value)
{
    int fd = open(SELINUX_ENFORCE_FILE, O_RDWR);
    if (fd < 0) {
        return false;
    }

    char buf[20];
    snprintf(buf, sizeof(buf), "%d", value);
    int ret = write(fd, buf, strlen(buf));
    close(fd);
    if (ret < 0) {
        return false;
    }

    return true;
}

}
}
