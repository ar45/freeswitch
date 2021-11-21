#include <mod_conference.h>

/// Replaces sub string with value.
/// Returns realocated memory with new string. In case if zero parameter passed or sub str not found, pointer to passed str returned.
static char * replace_str(const char *str, const char *sub_str, const char *val)
{
	unsigned int count = 0, size, num = strlen(str);
	char *result;
	const char *str_ptr = str, *prev_str_ptr;

	if (zstr(str) || zstr(sub_str) || zstr(val))
	{
		return (char *)str;
	}

	while ((str_ptr = strstr(str_ptr, sub_str)))
	{
		++count;
		str_ptr += strlen(sub_str);
	}

	if (count == 0)
	{
		return (char *)str;
	}

	size = strlen(str) - (strlen(sub_str) * count) + (strlen(val) * count) + 1;
	result = (char *)malloc(size);
	memset(result, 0, size);

	str_ptr = str;
	prev_str_ptr = str_ptr;
	while ((str_ptr = strstr(str_ptr, sub_str)))
	{
		num = str_ptr - prev_str_ptr;
		strncat(result, prev_str_ptr, num);
		strcat(result, val);
		str_ptr += strlen(sub_str);
		prev_str_ptr = str_ptr;
	}
	strncat(result, prev_str_ptr, strlen(prev_str_ptr));

	return result;
}

static switch_cache_db_handle_t *conference_db_get_handle(conference_db_t *db) {
	switch_cache_db_handle_t *handle = NULL;

	if (!zstr(db->odbc_dsn)) {
		if (switch_cache_db_get_db_handle_dsn(&handle, db->odbc_dsn) != SWITCH_STATUS_SUCCESS) {
			handle = NULL;
		}
	}

	return handle;
}

static void conference_db_execute_sql(conference_db_t *db, char *sql)
{
	char *err = NULL;
	switch_cache_db_handle_t *db_handle = conference_db_get_handle(db);

	if (db_handle != NULL)
	{
		switch_cache_db_execute_sql(db_handle, sql, &err);
		switch_cache_db_release_db_handle(&db_handle);

		if (err) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Conference db error: [%s]\n", err);
			switch_safe_free(err);
		}
	}
}

void conference_db_created(conference_obj_t *conference, switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char buff[0x15] = { 0 }; //uint64 max lenght
	char *sql_command = NULL;

	if (!zstr(conference->db.create_sql))
	{
		sprintf(buff, "%" PRIu64, conference->start_time);
		switch_channel_set_variable(channel, "conference_uuid", conference->uuid_str);
		switch_channel_set_variable(channel, "conference_start_time", buff);
		sql_command = switch_channel_expand_variables(channel, conference->db.create_sql);

		conference_db_execute_sql(&conference->db, sql_command);

		if (sql_command != conference->db.create_sql)
		{
			switch_safe_free(sql_command);
		}
	}
}

void conference_db_ended(conference_obj_t *conference)
{
	char *str_ptr;
	char buff[0x15] = { 0 }; //uint64 max lenght
	char *sql_command = NULL;

	if (!zstr(conference->db.end_sql))
	{
		sprintf(buff, "%" PRIu64, conference->end_time);
		str_ptr = replace_str(conference->db.end_sql, "${conference_uuid}", conference->uuid_str);
		sql_command = replace_str(str_ptr, "${conference_end_time}", buff);

		conference_db_execute_sql(&conference->db, sql_command);

		if (sql_command != str_ptr)
		{
			free((void *)sql_command);
		}
		if (str_ptr != conference->db.end_sql)
		{
			free((void *)str_ptr);
		}
	}
}

void conference_db_member_joined(conference_member_t *member)
{
	conference_obj_t *conference = member->conference;
	switch_channel_t *channel = member->channel;
	char buff[0x15] = { 0 }; //uint64 max lenght
	char *sql_command = NULL;

	if (!zstr(conference->db.user_join_sql))
	{
		switch_channel_set_variable(channel, "conference_uuid", conference->uuid_str);
		sprintf(buff, "%" PRIu32, member->id);
		switch_channel_set_variable(channel, "conference_member_id", buff);
		memset(buff, 0, sizeof(buff));
		sprintf(buff, "%" PRIu64, member->cdr_node->join_time);
		switch_channel_set_variable(channel, "conference_join_time", buff);
		sql_command = switch_channel_expand_variables(channel, conference->db.user_join_sql);

		conference_db_execute_sql(&conference->db, sql_command);

		if (sql_command != conference->db.user_join_sql)
		{
			switch_safe_free(sql_command);
		}
	}
}

void conference_db_member_left(conference_member_t *member)
{
	conference_obj_t *conference = member->conference;
	char buff[0x15] = { 0 }; //uint64 max lenght
	char *sql_command = NULL;
	char *str_ptr1;
	char *str_ptr2;

	if (!zstr(conference->db.user_leave_sql))
	{
		str_ptr1 = replace_str(conference->db.user_leave_sql, "${conference_uuid}", conference->uuid_str);
		sprintf(buff, "%" PRIu32, member->id);
		str_ptr2 = replace_str(str_ptr1, "${conference_member_id}", buff);
		memset(buff, 0, sizeof(buff));
		sprintf(buff, "%" PRIu64, member->cdr_node->leave_time);
		sql_command = replace_str(str_ptr2, "${conference_leave_time}", buff);

		conference_db_execute_sql(&conference->db, sql_command);

		if (sql_command != str_ptr2)
		{
			free((void *)sql_command);
		}
		if (str_ptr2 != str_ptr1)
		{
			free((void *)str_ptr2);
		}
		if (str_ptr1 != conference->db.user_leave_sql)
		{
			free((void *)str_ptr1);
		}
	}
}
