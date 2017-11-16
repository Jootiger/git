#include "cache.h"
#include "commit.h"
#include "config.h"
#include "revision.h"
#include "argv-array.h"
#include "list-objects.h"
#include "list-objects-filter.h"
#include "list-objects-filter-options.h"

/*
 * Return 1 if the given string needs armoring because of "special"
 * characters that may cause injection problems when a command passes
 * the argument to a subordinate command (such as when upload-pack
 * launches pack-objects).
 *
 * The usual alphanumeric and key punctuation do not trigger it.
 */
static int arg_needs_armor(const char *arg)
{
	const unsigned char *p;

	for (p = (const unsigned char *)arg; *p; p++) {
		if (*p >= 'a' && *p <= 'z')
			continue;
		if (*p >= 'A' && *p <= 'Z')
			continue;
		if (*p >= '0' && *p <= '9')
			continue;
		if (*p == '-' || *p == '_' || *p == '.' || *p == '/')
			continue;

		return 1;
	}
	return 0;
}

void armor_encode_arg(struct strbuf *buf, const char *arg)
{
	static const char hex[] = "0123456789abcdef";
	const unsigned char *p;

	for (p = (const unsigned char *)arg; *p; p++) {
		unsigned int val = *p;
		strbuf_addch(buf, hex[val >> 4]);
		strbuf_addch(buf, hex[val & 0xf]);
	}
}

int armor_decode_arg(struct strbuf *buf, const char *arg)
{
	const char *p;

	for (p = arg; *p; p += 2) {
		int val = hex2chr(p);
		unsigned char ch;
		if (val < 0)
			return -1;
		ch = val;
		strbuf_addch(buf, ch);
	}
	return 0;
}

/*
 * Parse value of the argument to the "filter" keword.
 * On the command line this looks like:
 *       --filter=<arg>
 * and in the pack protocol as:
 *       "filter" SP <arg>
 *
 * The filter keyword will be used by many commands.
 * See Documentation/rev-list-options.txt for allowed values for <arg>.
 *
 * Capture the given arg as the "raw_value".  This can be forwarded to
 * subordinate commands when necessary.  We also "intern" the arg for
 * the convenience of the current command.
 */
int parse_list_objects_filter(struct list_objects_filter_options *filter_options,
			      const char *arg)
{
	const char *v0;

	if (filter_options->choice)
		die(_("multiple object filter types cannot be combined"));

	filter_options->raw_value = strdup(arg);

	if (!strcmp(arg, "blob:none")) {
		filter_options->choice = LOFC_BLOB_NONE;
		return 0;
	}

	if (skip_prefix(arg, "blob:limit=", &v0)) {
		if (!git_parse_ulong(v0, &filter_options->blob_limit_value))
			die(_("invalid filter-spec expression '%s'"), arg);
		filter_options->choice = LOFC_BLOB_LIMIT;
		return 0;
	}

	if (skip_prefix(arg, "sparse:oid=", &v0)) {
		struct object_context oc;
		struct object_id sparse_oid;

		/*
		 * Try to parse <oid-expression> into an OID for the current
		 * command, but DO NOT complain if we don't have the blob or
		 * ref locally.
		 */
		if (!get_oid_with_context(v0, GET_OID_BLOB,
					  &sparse_oid, &oc))
			filter_options->sparse_oid_value = oiddup(&sparse_oid);
		filter_options->choice = LOFC_SPARSE_OID;
		if (arg_needs_armor(v0))
			filter_options->requires_armor = v0 - arg;
		return 0;
	}

	if (skip_prefix(arg, "sparse:path=", &v0)) {
		filter_options->choice = LOFC_SPARSE_PATH;
		filter_options->sparse_path_value = strdup(v0);
		if (arg_needs_armor(v0))
			filter_options->requires_armor = v0 - arg;
		return 0;
	}

	if (skip_prefix(arg, "x:", &v0)) {
		int r;
		struct strbuf buf = STRBUF_INIT;
		if (armor_decode_arg(&buf, v0) < 0)
			die(_("invalid filter-spec expression '%s'"), arg);
		r = parse_list_objects_filter(filter_options, buf.buf);
		strbuf_release(&buf);
		return r;
	}

	die(_("invalid filter-spec expression '%s'"), arg);
	return 0;
}

int opt_parse_list_objects_filter(const struct option *opt,
				  const char *arg, int unset)
{
	struct list_objects_filter_options *filter_options = opt->value;

	assert(arg);
	assert(!unset);

	return parse_list_objects_filter(filter_options, arg);
}
