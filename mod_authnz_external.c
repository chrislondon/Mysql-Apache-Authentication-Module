/* ====================================================================
* Copyright (c) 1995 The Apache Group.  All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in
*    the documentation and/or other materials provided with the
*    distribution.
*
* 3. All advertising materials mentioning features or use of this
*    software must display the following acknowledgment:
*    "This product includes software developed by the Apache Group
*    for use in the Apache HTTP server project (http://www.apache.org/)."
*
* 4. The names "Apache Server" and "Apache Group" must not be used to
*    endorse or promote products derived from this software without
*    prior written permission.
*
* 5. Redistributions of any form whatsoever must retain the following
*    acknowledgment:
*    "This product includes software developed by the Apache Group
*    for use in the Apache HTTP server project (http://www.apache.org/)."
*
* THIS SOFTWARE IS PROVIDED BY THE APACHE GROUP ``AS IS'' AND ANY
* EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
* PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE APACHE GROUP OR
* IT'S CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
* ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
* OF THE POSSIBILITY OF SUCH DAMAGE.
* ====================================================================
*
* This software consists of voluntary contributions made by many
* individuals on behalf of the Apache Group and was originally based
* on public domain software written at the National Center for
* Supercomputing Applications, University of Illinois, Urbana-Champaign.
* For more information on the Apache Group and the Apache HTTP server
* project, please see <http://www.apache.org/>.
*
*/

#include "apr_lib.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "mod_auth.h"
#include "apr_signal.h"

#define APR_WANT_STRFUNC
#include "apr_want.h"
#include "apr_strings.h"

#include "httpd.h"
#include "http_config.h"
#include "http_core.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"   /* for ap_hook_(check_user_id | auth_checker)*/

#if APR_HAVE_UNISTD_H
	#include <unistd.h>
#endif

#ifndef STANDARD20_MODULE_STUFF
	#error This module requires Apache 2.2.0 or later.
#endif

/* Names of environment variables used to pass data to authenticator */
#define ENV_USER	"USER"
#define ENV_PASS	"PASS"
#define ENV_GROUP	"GROUP"
#define ENV_URI		"URI"
#define ENV_IP		"IP"
#define ENV_HOST	"HOST"		/* Remote Host */
#define ENV_HTTP_HOST	"HTTP_HOST"	/* Local Host */
#define ENV_CONTEXT	"CONTEXT"	/* Arbitrary Data from Config */
/* Undefine this if you do not want cookies passed to the script */
#define ENV_COOKIE	"COOKIE"

/* Maximum number of arguments passed to an authenticator */
#define MAX_ARG 32

/* Default authentication method - "pipe", "environment" or "checkpass" */
#define DEFAULT_METHOD "pipe"

/*
* Structure for the module itself.  The actual definition of this structure
* is at the end of the file.
*/
module AP_MODULE_DECLARE_DATA authnz_external_module;


/* Comment out this line if you don't want to use custom hardcoded functions
*  This is must be used for Windows as I can't find a way to get around the
*  sig functions
*/
#define _HARDCODE_

#ifdef _HARDCODE_

/********************************************************************************
* AppsToBe Mysql Authentication
* Author: Chris London
********************************************************************************/
/* Necessary Windows includes for using MySQL on WAMP */
#ifdef _WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#endif

#include <mysql.h>

int a2b_authenticate(request_rec *r, const char *user_passwd, char *config_path) {
	MYSQL *conn;
	//MYSQL_RES *res;
	MYSQL_STMT *stmt;
	static char key[25], val[25], server[25], user[25], password[25], 
		database[25], utable[25], uid[25], uufield[25], upfield[25], 
		atable[25], aid[25], afield[25], jtable[25], juid[25], jaid[25], 
		hash[25];
	
	int l = 0;
	char *repo_name;
	static char query[1000];

	 // Bind variables
	MYSQL_BIND param[3], result[1];

	int valid_user;
	char param_username[50], param_password[50], param_project[50];
	unsigned long username_length, password_length, project_length;
	my_bool is_null[1];

	FILE *f = fopen(config_path, "r");

	if (f == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to open config file %s", config_path);
			return -5;
	} else {
		// Load config values
		while (fscanf(f, "%s %s", key, val) != EOF) {
			if (!strcmp(key, "server")) {
				strcpy(server, val);
			} else if (!strcmp(key, "user")) {
				strcpy(user, val);
			} else if (!strcmp(key, "password")) {
				strcpy(password, val);
			} else if (!strcmp(key, "database")) {
				strcpy(database, val);
			} else if (!strcmp(key, "utable")) {
				strcpy(utable, val);
			} else if (!strcmp(key, "uid")) {
				strcpy(uid, val);
			} else if (!strcmp(key, "uufield")) {
				strcpy(uufield, val);
			} else if (!strcmp(key, "upfield")) {
				strcpy(upfield, val);
			} else if (!strcmp(key, "atable")) {
				strcpy(atable, val);
			} else if (!strcmp(key, "aid")) {
				strcpy(aid, val);
			} else if (!strcmp(key, "afield")) {
				strcpy(afield, val);
			} else if (!strcmp(key, "jtable")) {
				strcpy(jtable, val);
			} else if (!strcmp(key, "juid")) {
				strcpy(juid, val);
			} else if (!strcmp(key, "jaid")) {
				strcpy(jaid, val);
			} else if (!strcmp(key, "hash")) {
				strcpy(hash, val);
			} else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Extra config field: %s %s", key, val);
			}
		}

		fclose (f);
	}
   
	 
	conn = mysql_init(NULL);
	if (!mysql_real_connect(conn, server, user, password, database, 0, NULL, 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unable to connect to MySQL database using: %s %s ***** %s", server, user, database);
		return -12;
	}

	// Figure out the project name.
	// Expecting: (.*)/[Project Name].(.*)
	// valid: /git/test.git (test)
	// valid: /test.git (test)
	// valid: /i-eat/do.nuts (do)
	while (*r->uri != '.' && *r->uri != '\0') r->uri++;

	r->uri--;

	while (*r->uri != '/') {
		l++;
		r->uri--;
	}
	r->uri++;

	repo_name = (char*) malloc(l+1);
	strncpy(repo_name, r->uri, l);
	repo_name[l] = '\0';
	
	/*
	* User auth query:
	*
	* SELECT * FROM `$utable` u
	* JOIN `$jtable` j ON u.`$uid`=j.`$juid` AND u.`$uufield`='$user_name' AND u.`$upfield`=$hash('$user_password')
	* JOIN `$atable` a ON j.`$jaid`=a.`$aid` AND a.`$afield`='$repo_name'
	* LIMIT 1
	*
	* Example:
	* SELECT * FROM `users` u
	* JOIN `applications_users` j ON u.`id`=j.`user_id` AND u.`username`='chris' AND u.`password`=SHA1('cookie')
	* JOIN `applications` a ON j.`application_id`=a.`id` AND a.`repo_name`='test'
	* LIMIT 1
	*
	* This is designed for a many-to-many relationship:
	* users: id, username, password
	* applications_users: user_id, application_id
	* applications: id, repo_name
	*/
	sprintf(query, "SELECT COUNT(*) FROM `%s` u JOIN `%s` j ON u.`%s`=j.`%s` AND u.`%s`=? AND u.`%s`=%s(?) JOIN `%s` a ON j.`%s`=a.`%s` AND a.`%s`=? LIMIT 1", utable, jtable, uid, juid, uufield, upfield, hash, atable, jaid, aid, afield);

	// Allocate statement handler
	stmt = mysql_stmt_init(conn);

	if (!stmt) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not initialize statement handler");
		return -5;
	}

	// Prepare the statement
	if (mysql_stmt_prepare(stmt, query, strlen(query)) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not prepare statement");
		return -5;
	}
	
	// Initialize the result column structures
	memset (param, 0, sizeof (param)); /* zero the structures */
	memset (result, 0, sizeof (result)); /* zero the structures */

	// Init param structure
	// Username
	param[0].buffer_type    = MYSQL_TYPE_STRING;
	param[0].buffer         = (char *) &param_username;
	param[0].buffer_length  = 50;
	param[0].is_null		= 0;
	param[0].length         = &username_length;

	// Password
	param[1].buffer_type    = MYSQL_TYPE_STRING;
	param[1].buffer         = (char *) &param_password;
	param[1].buffer_length  = 50;
	param[1].is_null		= 0;
	param[1].length         = &password_length;

	// Project
	param[2].buffer_type    = MYSQL_TYPE_STRING;
	param[2].buffer         = (char *) &param_project;
	param[2].buffer_length  = 50;
	param[2].is_null		= 0;
	param[2].length         = &project_length;

	// Result
	result[0].buffer_type    = MYSQL_TYPE_LONG;
	result[0].buffer         = (void *) &valid_user;
	result[0].is_unsigned    = 0;
	result[0].is_null        = &is_null[0];
	result[0].length         = 0;

	// Bind param structure to statement
	if (mysql_stmt_bind_param(stmt, param) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not bind parameters");
		return -5;
	}
	
	// Bind result
	if (mysql_stmt_bind_result(stmt, result) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not bind results");
		return -5;
	}
	
	// Set bind parameters
	strncpy(param_username, r->user, 50);
	username_length = strlen(param_username);

	strncpy(param_password, user_passwd, 50);
	password_length = strlen(param_password);

	strncpy(param_project, repo_name, 50);
	project_length = strlen(param_project);
	
	// Execute!!
	if (mysql_stmt_execute(stmt) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not execute statement");
		return -5;
	}
	
	if (mysql_stmt_store_result(stmt) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not buffer result set");
		return -5;
	}
	
	// Fetch
	if(mysql_stmt_fetch (stmt) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Could not fetch results");
		return -5;
	}

	if (valid_user == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Invalid User: %s %s %s", r->user, user_passwd, *stmt);
		mysql_stmt_free_result(stmt); /* deallocate result set */
		mysql_stmt_close(stmt);
		mysql_close(conn);
		free(repo_name);
		return 1;
	}

	 // Deallocate result set
	 mysql_stmt_free_result(stmt); /* deallocate result set */

	 // Close the statement
	 mysql_stmt_close(stmt);

	// Close Database
	mysql_close(conn);

	free(repo_name); 
   
	return 0;
}
/********************************************************************************
* END AppsToBe Mysql Authentication
********************************************************************************/

#endif


/*
*  Data types for per-directory and per-server configuration
*/

typedef struct
{
	apr_array_header_t *auth_name; /* Auth keyword for current dir */
	char *group_name;		 /* Group keyword for current dir */
	char *context;		 /* Context string from AuthExternalContext */
	int  authoritative;		 /* Are we authoritative in current dir? */
	int  groupsatonce;		 /* Check all groups in one call in this dir? */
	char *grouperror;		 /* What to return if group auth fails */

} authnz_external_dir_config_rec;


typedef struct
{
	apr_table_t *auth_path;	 /* Hash mapping auth keywords to paths */
	apr_table_t *auth_method;	 /* Hash mapping auth keywords to methods */

	apr_table_t *group_path;	 /* Hash mapping group keywords to paths */
	apr_table_t *group_method;	 /* Hash mapping group keywords to methods */

} authnz_external_svr_config_rec;


/*
* Creators for per-dir and server configurations.  These are called
* via the hooks in the module declaration to allocate and initialize
* the per-directory and per-server configuration data structures declared
* above.
*/

static void *create_authnz_external_dir_config(apr_pool_t *p, char *d)
{
	authnz_external_dir_config_rec *dir= (authnz_external_dir_config_rec *)
		apr_palloc(p, sizeof(authnz_external_dir_config_rec));

	dir->auth_name= apr_array_make(p,2,sizeof(const char *));	/* no default */
	dir->group_name= NULL;	/* no default */
	dir->context= NULL;		/* no default */
	dir->authoritative= 1;	/* strong by default */
	dir->groupsatonce= 1;	/* default to on */
	dir->grouperror= NULL;	/* default to 401 */
	return dir;
}


static void *create_authnz_external_svr_config( apr_pool_t *p, server_rec *s)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		apr_palloc(p, sizeof(authnz_external_svr_config_rec));

	svr->auth_method=  apr_table_make(p, 4);
	svr->auth_path=    apr_table_make(p, 4);
	svr->group_method= apr_table_make(p, 4);
	svr->group_path=   apr_table_make(p, 4);
	/* Note: 4 is only initial hash size - they can grow bigger) */

	return (void *)svr;
}

/*
* Handler for a DefineExternalAuth server config line
*/

static const char *def_extauth(cmd_parms *cmd, void *dummy, const char *keyword,
	const char *method, const char *path)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->auth_path,   keyword, path );
	apr_table_set( svr->auth_method, keyword, method );

	return NULL;
}


/*
* Handler for a DefineExternalGroup server config line
*/

static const char *def_extgroup(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method, const char *path)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->group_path,   keyword, path );
	apr_table_set( svr->group_method, keyword, DEFAULT_METHOD );

	return NULL;
}



/*
* Handler for a AddExternalAuth server config line - add a external auth
* type to the server configuration
*/

static const char *add_extauth(cmd_parms *cmd, void *dummy, const char *keyword,
	const char *path)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->auth_path,   keyword, path );
	apr_table_set( svr->auth_method, keyword, DEFAULT_METHOD );

	return NULL;
}


/*
* Handler for a AddExternalGroup server config line - add a external group
* type to the server configuration
*/

static const char *add_extgroup(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *path)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->group_path,   keyword, path );
	apr_table_set( svr->group_method, keyword, DEFAULT_METHOD );

	return NULL;
}

/*
* Handler for a SetExternalAuthMethod server config line - change an external
* auth method in the server configuration
*/

static const char *set_authnz_external_method(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->auth_method, keyword, method );

	return NULL;
}


/*
* Handler for a SetExternalGroupMethod server config line - change an external
* group method in the server configuration
*/

static const char *set_extgroup_method(cmd_parms *cmd, void *dummy,
	const char *keyword, const char *method)
{
	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config( cmd->server->module_config,
		&authnz_external_module);

	apr_table_set( svr->group_method, keyword, method );

	return NULL;
}

/* Append an argument to an array defined by the offset */
static const char *append_array_slot(cmd_parms *cmd, void *struct_ptr,
	const char *arg)
{
	int offset = (int)(long)cmd->info;
	apr_array_header_t *array=
		*(apr_array_header_t **)((char *)struct_ptr + offset);

	*(const char **)apr_array_push(array)= apr_pstrdup(array->pool, arg);

	return NULL;
}


/*
* Config file commands that this module can handle
*/

static const command_rec authnz_external_cmds[] =
{
	AP_INIT_ITERATE("AuthExternal",
	append_array_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec,auth_name),
	OR_AUTHCFG,
	"one (or more) keywords indicating which authenticators to use"),

	AP_INIT_TAKE3("DefineExternalAuth",
	def_extauth,
	NULL,
	RSRC_CONF,
	"a keyword followed by auth method and path to authentictor"),

	AP_INIT_TAKE2("AddExternalAuth",
	add_extauth,
	NULL,
	RSRC_CONF,
	"a keyword followed by a path to the authenticator program"),

	AP_INIT_TAKE2("SetExternalAuthMethod",
	set_authnz_external_method,
	NULL,
	RSRC_CONF,
	"a keyword followed by the method by which the data is passed"),

	AP_INIT_TAKE1("GroupExternal",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, group_name),
	OR_AUTHCFG,
	"a keyword indicating which group checker to use"),

	AP_INIT_TAKE3("DefineExternalGroup",
	def_extgroup,
	NULL,
	RSRC_CONF,
	"a keyword followed by auth method type and path to group checker"),

	AP_INIT_TAKE2("AddExternalGroup",
	add_extgroup,
	NULL,
	RSRC_CONF,
	"a keyword followed by a path to the group check program"),

	AP_INIT_TAKE2("SetExternalGroupMethod",
	set_extgroup_method,
	NULL,
	RSRC_CONF,
	"a keyword followed by the method by which the data is passed"),

	AP_INIT_FLAG("GroupExternalAuthoritative",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, authoritative),
	OR_AUTHCFG,
	"Set to 'off' to allow access control to be passed along to lower "
	"modules if this module can't confirm access rights" ),

	AP_INIT_FLAG("AuthzExternalAuthoritative",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, authoritative),
	OR_AUTHCFG,
	"Old version of 'GroupExternalAuthoritative'" ),

	AP_INIT_TAKE1("AuthExternalContext",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, context),
	OR_AUTHCFG,
	"An arbitrary context string to pass to the authenticator in the "
	ENV_CONTEXT " environment variable"),

	AP_INIT_TAKE1("GroupExternalError",
	ap_set_string_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, grouperror),
	OR_AUTHCFG,
	"HTTP error code to return when group authentication fails"),

	AP_INIT_FLAG("GroupExternalManyAtOnce",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, groupsatonce),
	OR_AUTHCFG,
	"Set to 'off' if group authenticator cannot handle multiple group "
	"names in one invocation" ),

	AP_INIT_FLAG("AuthExternalGroupsAtOnce",
	ap_set_flag_slot,
	(void *)APR_OFFSETOF(authnz_external_dir_config_rec, groupsatonce),
	OR_AUTHCFG,
	"Old version of 'GroupExternalManyAtOnce'" ),

	{ NULL }
};


/* Called from apr_proc_create() if there are errors during launch of child
* process.  Mostly just lifted from mod_cgi.
*/

static void extchilderr(apr_pool_t *p, apr_status_t err, const char *desc)
{
	apr_file_t *stderr_log;
	char errbuf[200];
	apr_file_open_stderr(&stderr_log, p);
	apr_file_printf(stderr_log,"%s: (%d) %s\n", ap_escape_logitem(p,desc),
		err, apr_strerror(err,errbuf,sizeof(errbuf)));
}


/*
* Run an external authentication program using the given method for passing
* in the data.  The login name is always passed in.   Dataname is "GROUP" or
* "PASS" and data is the group list or password being checked.  To launch
* a detached daemon, run this with extmethod=NULL.
*
* If the authenticator was run, we return the numeric code from the
* authenticator, normally 0 if the login was valid, some small positive
* number if not.  If we were not able to run the authenticator, we log
* an error message and return a numeric error code:
*
*   -1   Could not execute authenticator, usually a path or permission problem
*   -2   The external authenticator crashed or was killed.
*   -3   Could not create process attribute structure
*   -4   apr_proc_wait() did not return a status code.  Should never happen.
*   -5   apr_proc_wait() returned before child finished.  Should never happen.
*/

static int exec_external(const char *extpath, const char *extmethod,
	const request_rec *r, const char *dataname, const char *data)
{
	conn_rec *c= r->connection;
	apr_pool_t *p= r->pool;
	int isdaemon, usecheck= 0, usepipeout= 0, usepipein= 0;
	apr_procattr_t *procattr;
	apr_proc_t proc;
	apr_status_t rc= APR_SUCCESS;
	char *child_env[12];
	char *child_arg[MAX_ARG+2];
	const char *t;
	int i, status= -4;
	apr_exit_why_e why= APR_PROC_EXIT;

/* Disabling sigfunc for windows */
#ifndef _WIN32
	apr_sigfunc_t *sigchld;
#endif

	/* Set various flags based on the execution method */

	isdaemon= (extmethod == NULL);
	if (!isdaemon)
	{
		usecheck= extmethod && !strcasecmp(extmethod, "checkpassword");
		usepipeout= usecheck || (extmethod && !strcasecmp(extmethod, "pipes"));
		usepipein= usepipeout || (extmethod && !strcasecmp(extmethod, "pipe"));
	}

	/* Create the environment for the child.  Daemons don't get these, they
	* just inherit apache's environment variables.
	*/

	if (!isdaemon)
	{
		const char *cookie, *host, *remote_host;
		authnz_external_dir_config_rec *dir= (authnz_external_dir_config_rec *)
			ap_get_module_config(r->per_dir_config, &authnz_external_module);
		i= 0;

		if (!usepipein)
		{
			/* Put user name and password/group into environment */
			child_env[i++]= apr_pstrcat(p, ENV_USER"=", r->user, NULL);
			child_env[i++]= apr_pstrcat(p, dataname, "=", data, NULL);
		}

		child_env[i++]= apr_pstrcat(p, "PATH=", getenv("PATH"), NULL);

		child_env[i++]= apr_pstrcat(p, "AUTHTYPE=", dataname, NULL);

		remote_host= ap_get_remote_host(c, r->per_dir_config, REMOTE_HOST,NULL);
		if (remote_host != NULL)
			child_env[i++]= apr_pstrcat(p, ENV_HOST"=", remote_host,NULL);

		if (c->remote_ip)
			child_env[i++]= apr_pstrcat(p, ENV_IP"=", c->remote_ip, NULL);

		if (r->uri)
			child_env[i++]= apr_pstrcat(p, ENV_URI"=", r->uri, NULL);

		if ((host= apr_table_get(r->headers_in, "Host")) != NULL)
			child_env[i++]= apr_pstrcat(p, ENV_HTTP_HOST"=", host, NULL);

		if (dir->context)
			child_env[i++]= apr_pstrcat(r->pool, ENV_CONTEXT"=",
			dir->context, NULL);

#ifdef ENV_COOKIE
		if ((cookie= apr_table_get(r->headers_in, "Cookie")) != NULL)
			child_env[i++]= apr_pstrcat(p, ENV_COOKIE"=", cookie, NULL);
#endif
		/* NOTE:  If you add environment variables,
		*   remember to increase the size of the child_env[] array */

		/* End of environment */
		child_env[i]= NULL;
	}

	/* Construct argument array */
	for (t= extpath, i=0; *t != '\0' && (i <= MAX_ARG + 1);
		child_arg[i++]= ap_getword_white(p, &t)) {}
	child_arg[i]= NULL;

	/* Create the process attribute structure describing the script we
	* want to run using the Thread/Process functions from the Apache
	* portable runtime library. */

	if (((rc= apr_procattr_create(&procattr, p)) != APR_SUCCESS) ||

		/* should we create pipes to stdin, stdout and stderr? */
		((rc= apr_procattr_io_set(procattr,
		(usepipein && !usecheck) ? APR_FULL_BLOCK : APR_NO_PIPE,
		usepipeout ? APR_FULL_BLOCK : APR_NO_PIPE,
		(usepipein && usecheck) ? APR_FULL_BLOCK : APR_NO_PIPE))
		!= APR_SUCCESS ) ||

		/* will give full path of program and make a new environment */
		((rc= apr_procattr_cmdtype_set(procattr,
		isdaemon ? APR_PROGRAM_ENV : APR_PROGRAM)) != APR_SUCCESS) ||

		/* detach the child only if it is a daemon */
		((rc= apr_procattr_detach_set(procattr, isdaemon)) != APR_SUCCESS) ||

		/* function to call if child has error after fork, before exec */
		((rc= apr_procattr_child_errfn_set(procattr, extchilderr)
		!= APR_SUCCESS)))
	{
		/* Failed.  Probably never happens. */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"could not set child process attributes");
		return -3;
	}

	/* Sometimes other modules wil mess up sigchild.  Need to fix it for
	* the wait call to work correctly.  */
/* Disabling sigfunc for windows */
#ifndef _WIN32
	sigchld= apr_signal(SIGCHLD,SIG_DFL);
#endif

	/* Start the child process */
	rc= apr_proc_create(&proc, child_arg[0],
		(const char * const *)child_arg,
		(const char * const *)child_env, procattr, p);
	if (rc != APR_SUCCESS)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"Could not run external authenticator: %d: %s", rc,
			child_arg[0]);
		return -1;
	}

	if (isdaemon) return 0;

	apr_pool_note_subprocess(p, &proc, APR_KILL_AFTER_TIMEOUT);

	if (usepipein)
	{
		/* Select appropriate pipe to write to */
		apr_file_t *pipe= (usecheck ? proc.err : proc.in);

		/* Send the user */
		apr_file_write_full(pipe, r->user, strlen(r->user), NULL);
		apr_file_putc(usecheck ? '\0' : '\n', pipe);

		/* Send the password */
		apr_file_write_full(pipe, data, strlen(data), NULL);
		apr_file_putc(usecheck ? '\0' : '\n', pipe);

		/* Send dummy timestamp for checkpassword */
		if (usecheck) apr_file_write_full(pipe, "0", 2, NULL);

		/* Close the file */
		apr_file_close(pipe);
	}

	/* Wait for the child process to terminate, and get status */
	rc= apr_proc_wait(&proc,&status,&why,APR_WAIT);

	/* Restore sigchild to whatever it was before we reset it */
/* Disabling sigfunc for windows */
#ifndef _WIN32
	apr_signal(SIGCHLD,sigchld);
#endif

	if (!APR_STATUS_IS_CHILD_DONE(rc))
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rc, r,
			"Could not get status from child process");
		return -6;
	}
	if (!APR_PROC_CHECK_EXIT(why))
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"External authenticator died on signal %d",status);
		return -2;
	}

	return status;
}


/* Call the hardcoded function specified by the external path.  Of course,
* you'll have to write the hardcoded functions yourself and insert them
* into this source file, as well as inserting a call to them into this
* routine.
*/

static int exec_hardcode(request_rec *r, const char *extpath,
	const char *password)
{
#ifdef _HARDCODE_
	char *check_type;		/* Pointer to HARDCODE type check  */
	char *config_file;		/* Pointer to HARDCODE config file */
	int standard_auth= 0;

	/* Parse a copy of extpath into type and filename */
	check_type= apr_pstrdup(r->pool, extpath);
	config_file= strchr(check_type, ':');
	if (config_file != NULL)
	{
		*config_file= '\0';		   /* Mark end of type */
		config_file++;       	           /* Start of filename */
	}

	/* This is where you make your function call.  Here is an example of
	* what one looks like:
	*
	*   if (strcmp(check_type,"RADIUS")==0)
	*      code= radcheck(r,password,config_file);
	*
	* Replace 'radcheck' with whatever the name of your function is.
	* Replace 'RADIUS' with whatever you are using as the <type> in:
	*     AddExternalAuth <keyword> function <type>:<config file>
	*/

	if (strcmp(check_type,"A2B_AUTHENTICATE")==0)
		standard_auth = a2b_authenticate(r, password, config_file);
	else
		standard_auth= -5;
	return standard_auth;
#else
	return -4;		/* If _HARDCODE_ is not defined, always fail */
#endif /* _HARDCODE_ */
}


static int authz_external_check_user_access(request_rec *r)
{
	authnz_external_dir_config_rec *dir= (authnz_external_dir_config_rec *)
		ap_get_module_config(r->per_dir_config, &authnz_external_module);

	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config(r->server->module_config, &authnz_external_module);

	int i, code, ret;
	int m= r->method_number;
	const char *extpath, *extmethod;
	char *extname= dir->group_name;
	int required_group= 0;
	const char *t, *w;
	const apr_array_header_t *reqs_arr= ap_requires(r);
	const char *filegroup= NULL;
	require_line *reqs;

	/* If no external authenticator has been configured, pass */
	if ( !extname ) return DECLINED;

	/* If there are no Require arguments, pass */
	if (!reqs_arr) return DECLINED;
	reqs=  (require_line *)reqs_arr->elts;


	/* Loop through the "Require" argument list */
	for(i= 0; i < reqs_arr->nelts; i++)
	{
		if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) continue;

		t= reqs[i].requirement;
		w= ap_getword_white(r->pool, &t);

		/* The 'file-group' directive causes mod_authz_owner to store the
		* group name of the file we are trying to access in a note attached
		* to the request.  It's our job to decide if the user actually is
		* in that group.  If the note is missing, we just decline.
		*/
		if ( !strcasecmp(w, "file-group"))
		{
			filegroup= apr_table_get(r->notes, AUTHZ_GROUP_NOTE);
			if (filegroup == NULL) continue;
		}

		if( !strcmp(w,"group") || filegroup != NULL)
		{
			required_group= 1;

			if (t[0] || filegroup != NULL)
			{
				/* Get the path and method associated with that external */
				if (!(extpath= apr_table_get(svr->group_path, extname)) ||
					!(extmethod= apr_table_get(svr->group_method,
					extname)))
				{
					errno= 0;
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"invalid GroupExternal keyword (%s)", extname);
					ap_note_basic_auth_failure(r);
					return HTTP_INTERNAL_SERVER_ERROR;
				}

				if (filegroup != NULL)
				{
					/* Check if user is in the group that owns the file */
					code= exec_external(extpath, extmethod, r, ENV_GROUP,
						filegroup);
					if (code == 0) return OK;
				}
				else if (dir->groupsatonce)
				{
					/* Pass rest of require line to authenticator */
					code= exec_external(extpath, extmethod, r, ENV_GROUP, t);
					if (code == 0) return OK;
				}
				else
				{
					/* Call authenticator once for each group name on line */
					do {
						w= ap_getword_conf(r->pool, &t);
						code= exec_external(extpath,
							extmethod, r, ENV_GROUP, w);
						if (code == 0) return OK;
					} while(t[0]);
				}
			}
		}
	}

	/* If we didn't see a 'require group' or aren't authoritive, decline */
	if (!required_group || !dir->authoritative)
		return DECLINED;

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
		"access to %s failed, reason: user %s not allowed access (%s)",
		r->uri, r->user, dir->grouperror);

	ap_note_basic_auth_failure(r);

	return (dir->grouperror && (ret= atoi(dir->grouperror)) > 0) ? ret :
		HTTP_UNAUTHORIZED;
}


/* Password checker for basic authentication - given a login/password,
* check if it is valid.  Returns one of AUTH_DENIED, AUTH_GRANTED,
* or AUTH_GENERAL_ERROR.
*/

static authn_status authn_external_check_password(request_rec *r,
	const char *user, const char *password)
{
	const char *extname, *extpath, *extmethod;
	int i;

	authnz_external_dir_config_rec *dir= (authnz_external_dir_config_rec *)
		ap_get_module_config(r->per_dir_config, &authnz_external_module);

	authnz_external_svr_config_rec *svr= (authnz_external_svr_config_rec *)
		ap_get_module_config(r->server->module_config,
		&authnz_external_module);
	int code= 1;

	/* Check if we are supposed to handle this authentication */
	if (dir->auth_name->nelts == 0)
	{
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"No AuthExternal name has been set");
		return AUTH_GENERAL_ERROR;
	}

	for (i= 0; i < dir->auth_name->nelts; i++)
	{
		extname= ((const char **)dir->auth_name->elts)[i];

		/* Get the path associated with that external */
		if (!(extpath= apr_table_get(svr->auth_path, extname)))
		{
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"Invalid AuthExternal keyword (%s)", extname);
			return AUTH_GENERAL_ERROR;
		}

		/* Do the authentication, by the requested method */
		extmethod= apr_table_get(svr->auth_method, extname);
		if ( extmethod && !strcasecmp(extmethod, "function") ) {
			code= exec_hardcode(r, extpath, password);
		} else {
			code= exec_external(extpath, extmethod, r, ENV_PASS, password);
		}

		/* If return code was zero, authentication succeeded */
		if (code == 0) return AUTH_GRANTED;

		/* Log a failed authentication */
		errno= 0;
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
			"AuthExtern %s [%s]: Failed (%d) for user %s",
			extname, extpath, code, r->user);
	}
	/* If no authenticators succeed, refuse authentication */
	return AUTH_DENIED;
}


#if 0
/* Password checker for digest authentication - given a login/password,
* check if it is valid.  Returns one of AUTH_USER_FOUND, AUTH_USER_NOT_FOUND,
* or AUTH_GENERAL_ERROR.   Not implemented at this time.
*/

auth_status *authn_external_get_realm_hash(request_rec *r, const char *user,
	const char *realm, char **rethash);
{
}
#endif


static const authn_provider authn_external_provider =
{
	&authn_external_check_password,
#if 0
	&authn_external_get_realm_hash
#else
	NULL		/* No support for digest authentication at this time */
#endif
};


static void register_hooks(apr_pool_t *p)
{
	ap_register_provider(p, AUTHN_PROVIDER_GROUP, "external", "0",
		&authn_external_provider);

	ap_hook_auth_checker(authz_external_check_user_access, NULL, NULL,
		APR_HOOK_MIDDLE);
}


module AP_MODULE_DECLARE_DATA authnz_external_module = {
	STANDARD20_MODULE_STUFF,
	create_authnz_external_dir_config,	  /* create per-dir config */
	NULL,			  /* merge per-dir config - dflt is override */
	create_authnz_external_svr_config, /* create per-server config */
	NULL,			  /* merge per-server config */
	authnz_external_cmds,	  /* command apr_table_t */
	register_hooks		  /* register hooks */
};
