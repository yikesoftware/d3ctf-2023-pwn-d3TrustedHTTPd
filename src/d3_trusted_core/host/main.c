#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>

#include <sys/mman.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/net.h>
#include <sys/un.h>
#include <signal.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <d3_trusted_core_ta.h>

#define FACE_DATA_SIZE 128
#define FACE_DATA_SIZE_BYTES (FACE_DATA_SIZE * sizeof(vec_float))
#define FACE_SIMILARITY_THRESHOLD 0.90
#define FACE_ID_EXPIRED_ROUND 1300000

typedef double vec_float;
int init_core_files();
int check_core_files();

TEEC_Context ctx;
TEEC_Session sess;
TEEC_UUID uuid = TA_D3_TRUSTED_CORE_UUID;

uint32_t state = 0;
uint32_t var_state = 0;
char *cursor = NULL;
char *username = NULL;
char *password = NULL;
char *session_id = NULL;
char *old_password = NULL;
char *new_password = NULL;
uint32_t get_similarity = 0;
uint32_t reset_face_id = 0;
uint32_t get_user_list_mode = 0;
vec_float *face_data = NULL;
vec_float similarity = 0.0;
user_info_out_t *user_info_out = NULL;
uint32_t user_list_out_count = 0;
user_info_out_t *user_list_out = NULL;
uint32_t parent_id;
uint32_t ext_id;
uint32_t ext_id_out = ~0;
char *filename;
char *new_filename;
uint32_t del_mode = 0;
char *dir_name;
uint32_t rm_mode = 0;
uint8_t *file_data;
uint32_t file_data_sz;
uint32_t max_read_sz = 0;

#define MAX_BUF_SIZE 0x2000
#define MAX_GLO_BUF_SIZE 0x2000
char global_buf[MAX_GLO_BUF_SIZE] = {0};

uint32_t test_mode = 0;

char *core_files[5] = {
	"/usr/sbin/tee-supplicant",
	"/usr/bin/optee_d3_trusted_core",
	"/usr/bin/mini_httpd",
	"/flag.txt",
	NULL
};

uint8_t core_files_sha256[5][TEE_SHA256_HASH_SIZE];

int parse_rpc_packet(int rpc_fd, char *reqbuf) {
	if(test_mode){
		cursor = NULL;
		username = NULL;
		password = NULL;
		session_id = NULL;
		old_password = NULL;
		new_password = NULL;
		get_similarity = 0;
		reset_face_id = 0;
		get_user_list_mode = 0;
		face_data = NULL;
		similarity = 0.0;
		user_info_out = NULL;
		user_list_out_count = 0;
		user_list_out = NULL;
		parent_id = ~0;
		ext_id = ~0;
		ext_id_out = ~0;
		filename = NULL;
		new_filename = NULL;
		del_mode = 0;
		dir_name = NULL;
		rm_mode = 0;
		file_data = NULL;
		file_data_sz = 0;
		max_read_sz = 0;
	}

	enum {
		STATE_EMPTY,
		STATE_INIT,
		STATE_ACTION,
		STATE_ACTION_CMD,
		STATE_ACTION_SECFS,
		STATE_ACTION_SYS,

		STATE_ACTION_CMD_AUTH_USER_PASSWD,
		STATE_ACTION_CMD_DO_AUTH_USER_PASSWD,
		STATE_ACTION_CMD_DO_AUTH_USER_PASSWD_DONE,

		STATE_ACTION_CMD_AUTH_USER_FACE_ID,
		STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID,
		STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE,
		STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE_GET_SIMILARITY,

		STATE_ACTION_CMD_AUTH_SESSION_ID,
		STATE_ACTION_CMD_DO_AUTH_SESSION_ID,
		STATE_ACTION_CMD_DO_AUTH_SESSION_ID_DONE,

		STATE_ACTION_CMD_USER_SUBCMD,
		STATE_ACTION_CMD_USER_INFO,
		STATE_ACTION_CMD_DO_USER_INFO,
		STATE_ACTION_CMD_DO_USER_INFO_DONE,
		STATE_ACTION_CMD_USER_LIST,
		STATE_ACTION_CMD_DO_USER_LIST,
		STATE_ACTION_CMD_DO_USER_LIST_DONE,		
		STATE_ACTION_CMD_USER_LOGOUT,
		STATE_ACTION_CMD_DO_USER_LOGOUT,
		STATE_ACTION_CMD_DO_USER_LOGOUT_DONE,
		STATE_ACTION_CMD_USER_PASSWD,
		STATE_ACTION_CMD_DO_USER_PASSWD,
		STATE_ACTION_CMD_DO_USER_PASSWD_DONE,
		STATE_ACTION_CMD_USER_ENABLE,
		STATE_ACTION_CMD_DO_USER_ENABLE,
		STATE_ACTION_CMD_DO_USER_ENABLE_DONE,
		STATE_ACTION_CMD_USER_DISABLE,
		STATE_ACTION_CMD_DO_USER_DISABLE,
		STATE_ACTION_CMD_DO_USER_DISABLE_DONE,
		STATE_ACTION_CMD_USER_KICKOUT,
		STATE_ACTION_CMD_DO_USER_KICKOUT,
		STATE_ACTION_CMD_DO_USER_KICKOUT_DONE,
		STATE_ACTION_CMD_USER_RESET,
		STATE_ACTION_CMD_DO_USER_RESET,
		STATE_ACTION_CMD_DO_USER_RESET_DONE,


		STATE_ACTION_SECFS_CREATE_FILE,
		STATE_ACTION_SECFS_DO_CREATE_FILE,
		STATE_ACTION_SECFS_DO_CREATE_FILE_DONE,
		STATE_ACTION_SECFS_DELETE_FILE,
		STATE_ACTION_SECFS_DO_DELETE_FILE,
		STATE_ACTION_SECFS_DO_DELETE_FILE_DONE,
		STATE_ACTION_SECFS_READ_FILE,
		STATE_ACTION_SECFS_DO_READ_FILE,
		STATE_ACTION_SECFS_DO_READ_FILE_DONE,
		STATE_ACTION_SECFS_UPDATE_FILE,
		STATE_ACTION_SECFS_DO_UPDATE_FILE,
		STATE_ACTION_SECFS_DO_UPDATE_FILE_DONE,
		STATE_ACTION_SECFS_FILE_INFO,
		STATE_ACTION_SECFS_DO_FILE_INFO,
		STATE_ACTION_SECFS_DO_FILE_INFO_DONE,
		STATE_ACTION_SECFS_RENAME_FILE,
		STATE_ACTION_SECFS_DO_RENAME_FILE,
		STATE_ACTION_SECFS_DO_RENAME_FILE_DONE,

		STATE_ACTION_SECFS_SLOTS_INFO,
		STATE_ACTION_SECFS_DO_SLOTS_INFO,
		STATE_ACTION_SECFS_DO_SLOTS_INFO_DONE,

		STATE_ACTION_SECFS_CREATE_DIR,
		STATE_ACTION_SECFS_DO_CREATE_DIR,
		STATE_ACTION_SECFS_DO_CREATE_DIR_DONE,
		STATE_ACTION_SECFS_DELETE_DIR,
		STATE_ACTION_SECFS_DO_DELETE_DIR,
		STATE_ACTION_SECFS_DO_DELETE_DIR_DONE,
		STATE_ACTION_SECFS_DIR_INFO,
		STATE_ACTION_SECFS_DO_DIR_INFO,
		STATE_ACTION_SECFS_DO_DIR_INFO_DONE,

		STATE_ACTION_SYS_CHECK_ALIVE,
		STATE_ACTION_SYS_DO_CHECK_ALIVE,
		STATE_ACTION_SYS_DO_CHECK_ALIVE_DONE,

		STATE_NORMAL_DONE,
		STATE_NORMAL_ERROR,
	};

	cursor = reqbuf;
	state = STATE_INIT;

	while(1){
		switch(state){
			case STATE_INIT:{
				if(!(strlen(cursor) >= 2 && cursor[0] == '!' && cursor[1] == '!')){
					state = STATE_NORMAL_ERROR;
				}
				cursor += 2;
				state = STATE_ACTION;
				break;
			}
			case STATE_ACTION:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
				} else{
					if(!strncasecmp(cursor, "command", 7)){
						cursor += 7;
						state = STATE_ACTION_CMD;
					} else if(!strncasecmp(cursor, "secfs", 5)){
						cursor += 5;
						state = STATE_ACTION_SECFS;
					} else if(!strncasecmp(cursor, "system", 6)){
						cursor += 6;
						state = STATE_ACTION_SYS;
					}
					else{
						state = STATE_NORMAL_ERROR;
					}
				}
				break;
			}
			case STATE_ACTION_CMD:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
				} else{
					if(!strncasecmp(cursor, "auth_user_passwd", 16)){
						cursor += 16;
						state = STATE_ACTION_CMD_AUTH_USER_PASSWD;
					}
					else if(!strncasecmp(cursor, "auth_user_face_id", 17)){
						cursor += 17;
						state = STATE_ACTION_CMD_AUTH_USER_FACE_ID;
					}
					else if(!strncasecmp(cursor, "auth_session_id", 15)){
						cursor += 15;
						state = STATE_ACTION_CMD_AUTH_SESSION_ID;
					}
					else if(!strncasecmp(cursor, "user", 4)){
						cursor += 4;
						state = STATE_ACTION_CMD_USER_SUBCMD;
					}
					else{
						state = STATE_NORMAL_ERROR;
					}
				}
				break;
			}
			case STATE_ACTION_SECFS:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
				} else{
					if(!strncasecmp(cursor, "create", 6)){
						cursor += 6;
						state = STATE_ACTION_SECFS_CREATE_FILE;
					} else if(!strncasecmp(cursor, "delete", 6)){
						cursor += 6;
						state = STATE_ACTION_SECFS_DELETE_FILE;
					} else if(!strncasecmp(cursor, "info", 4)){
						cursor += 4;
						while (*cursor == ' ' || *cursor == '\t')
							cursor++;
						if(!strncasecmp(cursor, "file", 4)){
							state = STATE_ACTION_SECFS_FILE_INFO;
							cursor += 4;
						} else if(!strncasecmp(cursor, "dir", 3)){
							state = STATE_ACTION_SECFS_DIR_INFO;
							cursor += 3;
						} else{
							state = STATE_NORMAL_ERROR;
						}
					} else if(!strncasecmp(cursor, "read", 4)){
						cursor += 4;
						state = STATE_ACTION_SECFS_READ_FILE;
					} else if(!strncasecmp(cursor, "update", 6)){
						cursor += 6;
						state = STATE_ACTION_SECFS_UPDATE_FILE;
					} else if(!strncasecmp(cursor, "rename", 6)){
						cursor += 6;
						state = STATE_ACTION_SECFS_RENAME_FILE;
					} else if(!strncasecmp(cursor, "slots", 5)){
						cursor += 5;
						state = STATE_ACTION_SECFS_SLOTS_INFO;
					} else if(!strncasecmp(cursor, "mkdir", 5)){
						cursor += 5;
						state = STATE_ACTION_SECFS_CREATE_DIR;
					} else if(!strncasecmp(cursor, "rmdir", 5)){
						cursor += 5;
						state = STATE_ACTION_SECFS_DELETE_DIR;
					} else{
						state = STATE_NORMAL_ERROR;
					}
				}
				break;				
			}
			case STATE_ACTION_SYS:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
				} else{
					if(!strncasecmp(cursor, "check_alive", 11)){
						cursor += 11;
						state = STATE_ACTION_SYS_CHECK_ALIVE;
					}
					else{
						state = STATE_NORMAL_ERROR;
					}
				}
				break;				
			}
			// ================================================================
			case STATE_ACTION_SYS_CHECK_ALIVE:{
				state = STATE_ACTION_SYS_DO_CHECK_ALIVE;
				break;
			}
			case STATE_ACTION_SYS_DO_CHECK_ALIVE:{
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_CHECK_ALIVE, &op, NULL);
				if (res != TEEC_SUCCESS){
					state = STATE_NORMAL_ERROR;
					break;
				}
				if (op.params[0].value.a != 0x6b6f6d69){
					state = STATE_NORMAL_ERROR;
					break;
				}
				if(check_core_files() != 0){
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_SYS_DO_CHECK_ALIVE_DONE;
				break;
			}
			case STATE_ACTION_SYS_DO_CHECK_ALIVE_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_AUTH_USER_PASSWD:{
				// parse username password
				#define VAR_STATE_USERNAME 0
				#define VAR_STATE_PASSWORD 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_USERNAME;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_USERNAME){
							username = strdup(argn_start);
							var_state = VAR_STATE_PASSWORD;
						}
						else if (var_state == VAR_STATE_PASSWORD){
							password = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_AUTH_USER_PASSWD;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_USER_PASSWD:{
				TEEC_Result res;
				TEEC_Operation op;
				if (username == NULL || password == NULL){
					state = STATE_NORMAL_ERROR;
					break;
				}
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = username;
				op.params[0].tmpref.size = strlen(username);
				op.params[1].tmpref.buffer = password;
				op.params[1].tmpref.size = strlen(password);
				op.params[2].tmpref.buffer = calloc(1, HTTP_SESSION_LEN+1);
				op.params[2].tmpref.size = HTTP_SESSION_LEN;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_AUTH_USER_PASSWD, &op, NULL);
				if (res != TEEC_SUCCESS){
					state = STATE_NORMAL_ERROR;
					break;
				}
				session_id = calloc(1, op.params[2].tmpref.size+1);
				memcpy(session_id, op.params[2].tmpref.buffer, op.params[2].tmpref.size);
				free(op.params[2].tmpref.buffer);
				free(username);
				username = NULL;
				free(password);
				password = NULL;
				state = STATE_ACTION_CMD_DO_AUTH_USER_PASSWD_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_USER_PASSWD_DONE:{
				if (session_id == NULL){
					state = STATE_NORMAL_ERROR;
					break;
				}
				write(rpc_fd, session_id, strlen(session_id));
				free(session_id);
				session_id = NULL;
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_AUTH_USER_FACE_ID:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					username = strdup(argn_start);
				}
				get_similarity = 0;
				if (strlen(cursor) != 0){
					if(strncasecmp(cursor, "get_similarity", 14) == 0){
						cursor += 14;
						get_similarity = 1;
					}
					else{
						state = STATE_NORMAL_ERROR;
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				write(rpc_fd, "<data>", 6);
				uint32_t face_data_size = FACE_DATA_SIZE*sizeof(vec_float);
				face_data = calloc(1, face_data_size+1);
				if(read(rpc_fd, face_data, face_data_size) != face_data_size){
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID:{
				TEEC_Result res;
				TEEC_Operation op;
				if (username == NULL || face_data == NULL){
					state = STATE_NORMAL_ERROR;
					break;
				}
				similarity = 0.0;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
				op.params[0].tmpref.buffer = username;
				op.params[0].tmpref.size = strlen(username);
				op.params[1].tmpref.buffer = face_data;
				op.params[1].tmpref.size = FACE_DATA_SIZE_BYTES;
				if(get_similarity){
					op.params[2].tmpref.buffer = NULL;
					op.params[2].tmpref.size = 0;			
					op.params[3].tmpref.buffer = &similarity;
					op.params[3].tmpref.size = sizeof(vec_float);
				} else {
					op.params[2].tmpref.buffer = calloc(1, HTTP_SESSION_LEN+1);
					op.params[2].tmpref.size = HTTP_SESSION_LEN;
					op.params[3].tmpref.buffer = NULL;
					op.params[3].tmpref.size = 0;
				}
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_AUTH_USER_FACE_ID, &op, NULL);
				if(get_similarity){
					// only return similarity, not care about session id
					free(username);
					username = NULL;
					free(face_data);
					face_data = NULL;
					state = STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE_GET_SIMILARITY;
					break;
				}
				if (res == TEEC_ERROR_NOT_SUPPORTED){
					write(rpc_fd, "<disabled>", 10);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res == TEEC_ERROR_SECURITY){
					write(rpc_fd, "<expired>", 9);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res != TEEC_SUCCESS){
					state = STATE_NORMAL_ERROR;
					break;
				}
				session_id = calloc(1, op.params[2].tmpref.size+1);
				memcpy(session_id, op.params[2].tmpref.buffer, op.params[2].tmpref.size);
				free(op.params[2].tmpref.buffer);
				free(username);
				username = NULL;
				free(face_data);
				face_data = NULL;
				state = STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE:{
				char *out = NULL;
				if (session_id == NULL){
					state = STATE_NORMAL_ERROR;
					break;
				}
				asprintf(&out, "%s", session_id);
				write(rpc_fd, out, strlen(out));
				free(session_id);
				free(out);
				session_id = NULL;
				state = STATE_NORMAL_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_USER_FACE_ID_DONE_GET_SIMILARITY:{
				char *out = NULL;
				asprintf(&out, "%.17g", similarity);
				write(rpc_fd, out, strlen(out));
				free(out);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_AUTH_SESSION_ID:{
				// parse session id				
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					session_id = strdup(argn_start);
				}
				state = STATE_ACTION_CMD_DO_AUTH_SESSION_ID;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_SESSION_ID:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_AUTH_SESSION_ID, &op, NULL);
				if (res == TEEC_ERROR_NOT_SUPPORTED){
					write(rpc_fd, "<disabled>", 10);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_CMD_DO_AUTH_SESSION_ID_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_AUTH_SESSION_ID_DONE:{
				write(rpc_fd, "<ok>", 4);
				free(session_id);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_SUBCMD:{
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;		
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					if (strncasecmp(argn_start, "info", 4) == 0){
						state = STATE_ACTION_CMD_USER_INFO;
						break;
					} else if (strncasecmp(argn_start, "list", 4) == 0){
						state = STATE_ACTION_CMD_USER_LIST;
						break;
					} else if (strncasecmp(argn_start, "passwd", 6) == 0){
						state = STATE_ACTION_CMD_USER_PASSWD;
						break;
					} else if (strncasecmp(argn_start, "logout", 6) == 0){
						state = STATE_ACTION_CMD_USER_LOGOUT;
						break;
					} else if (strncasecmp(argn_start, "kickout", 7) == 0){
						state = STATE_ACTION_CMD_USER_KICKOUT;
						break;
					} else if (strncasecmp(argn_start, "enable", 6) == 0){
						state = STATE_ACTION_CMD_USER_ENABLE;
						break;
					} else if (strncasecmp(argn_start, "disable", 7) == 0){
						state = STATE_ACTION_CMD_USER_DISABLE;
						break;
					} else if (strncasecmp(argn_start, "reset", 5) == 0){
						state = STATE_ACTION_CMD_USER_RESET;
						break;
					}
				}
				state = STATE_NORMAL_ERROR;
				break;				
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_INFO:{
				// parse session id				
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					session_id = strdup(argn_start);
				}
				//fprintf(stderr, "session_id to auth: %s\n", session_id);
				state = STATE_ACTION_CMD_DO_USER_INFO;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_INFO:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = calloc(sizeof(user_info_out_t)+1, 1);
				op.params[1].tmpref.size = sizeof(user_info_out_t);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_GET_USER_INFO, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				user_info_out = calloc(sizeof(user_info_out_t)+1, 1);
				memcpy(user_info_out, (user_info_out_t *)op.params[1].tmpref.buffer, sizeof(user_info_out_t));
				free(op.params[1].tmpref.buffer);
				state = STATE_ACTION_CMD_DO_USER_INFO_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_INFO_DONE:{
				write(rpc_fd, user_info_out, sizeof(user_info_out_t));
				free(session_id);
				free(user_info_out);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_LIST:{
				// parse session id				
				#define MODE_ALL 0
				#define MODE_NORMAL 1
				#define MODE_DISABLED 2
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					session_id = strdup(argn_start);
				}
				if(strlen(cursor) > 0){
					if(strncasecmp(cursor, "all", 3) == 0){
						get_user_list_mode = MODE_ALL;
					} else if(strncasecmp(cursor, "normal", 6) == 0){
						get_user_list_mode = MODE_NORMAL;
					} else if(strncasecmp(cursor, "disabled", 8) == 0){
						get_user_list_mode = MODE_DISABLED;
					} else{
						state = STATE_NORMAL_ERROR;
						break;
					}
				} else{
					get_user_list_mode = MODE_ALL; // default
				}
				state = STATE_ACTION_CMD_DO_USER_LIST;
			}
			case STATE_ACTION_CMD_DO_USER_LIST:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT, TEEC_MEMREF_TEMP_OUTPUT);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = 8; // max user count
				op.params[1].value.b = get_user_list_mode; // mode: ALL
				op.params[3].tmpref.buffer = calloc(sizeof(user_info_out_t)*10, 1);
				op.params[3].tmpref.size = sizeof(user_info_out_t)*8;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_GET_USER_LIST, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(op.params[3].tmpref.buffer);
					state = STATE_NORMAL_ERROR;
					break;
				}
				user_list_out_count = op.params[2].value.a;
				if(user_list_out_count > 0){
					user_list_out = calloc(user_list_out_count, sizeof(user_info_out_t));
					memcpy(user_list_out, (user_info_out_t *)op.params[3].tmpref.buffer, user_list_out_count*sizeof(user_info_out_t));
				}
				free(op.params[3].tmpref.buffer);
				state = STATE_ACTION_CMD_DO_USER_LIST_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_LIST_DONE:{
				char *out = NULL;
				asprintf(&out, "%d", user_list_out_count);
				write(rpc_fd, out, strlen(out));
				if(out) free(out);
				if(user_list_out_count == 0){
					free(session_id);
					state = STATE_NORMAL_DONE;
					break;
				}
				// use recv() to get the "<data>" tag
				char *recv_buf = calloc(1024, 1);
				if(recv(rpc_fd, recv_buf, 1024, 0) < 0){
					free(session_id);
					free(user_list_out);
					free(recv_buf);
					state = STATE_NORMAL_ERROR;
					break;
				}
				if(strncasecmp(recv_buf, "<data>", 6)){
					free(session_id);
					free(user_list_out);
					free(recv_buf);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(recv_buf);
				// write user_list_out to rpc_fd
				uint32_t w_count = user_list_out_count*sizeof(user_info_out_t);
				uint32_t w_offset = 0;
				while(w_offset < w_count){
					int wn = write(rpc_fd, (char *)user_list_out+w_offset, w_count-w_offset);
					if(wn < 0){
						state = STATE_NORMAL_ERROR;
						break;
					}
					w_offset += wn;
				}
				if(state == STATE_NORMAL_ERROR){
					free(session_id);
					free(user_list_out);
					break;
				}
				free(session_id);
				free(user_list_out);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_PASSWD:{
				// parse session_id old_password new_password
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_OLD_PASSWORD 1
				#define VAR_STATE_NEW_PASSWORD 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_OLD_PASSWORD;
						} else if (var_state == VAR_STATE_OLD_PASSWORD){
							password = strdup(argn_start);
							var_state = VAR_STATE_NEW_PASSWORD;
						} else if (var_state == VAR_STATE_NEW_PASSWORD){
							new_password = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_USER_PASSWD;
				break;				
			}
			case STATE_ACTION_CMD_DO_USER_PASSWD:{
				if(!session_id || !password || !new_password){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = password;
				op.params[1].tmpref.size = strlen(password);
				op.params[2].tmpref.buffer = new_password;
				op.params[2].tmpref.size = strlen(new_password);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_PASSWD, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(password);
					free(new_password);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				free(password);
				free(new_password);
				state = STATE_ACTION_CMD_DO_USER_PASSWD_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_PASSWD_DONE:{
				write(rpc_fd, "<ok>", 6);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_LOGOUT:{
				// parse session id				
				while(*cursor == ' ' || *cursor == '\t')
					cursor++;
				if(!(strlen(cursor) > 0)){
					state = STATE_NORMAL_ERROR;
					break;
				} else{
					char *argn_start = cursor;
					while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
						cursor++;
					if (*cursor != '\0'){
						*cursor = '\0';
						cursor++;
					}
					session_id = strdup(argn_start);
				}
				state = STATE_ACTION_CMD_DO_USER_LOGOUT;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_LOGOUT:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_LOGOUT, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_CMD_DO_USER_LOGOUT_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_LOGOUT_DONE:{
				write(rpc_fd, "<ok>", 4);
				free(session_id);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_KICKOUT:{
				// parse session_id user_name
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_USER_NAME 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_USER_NAME;
						} else if (var_state == VAR_STATE_USER_NAME){
							username = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_USER_KICKOUT;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_KICKOUT:{
				if(!session_id || !username){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = username;
				op.params[1].tmpref.size = strlen(session_id);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_KICKOUT, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(username);
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_CMD_DO_USER_KICKOUT_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_KICKOUT_DONE:{
				write(rpc_fd, "<ok>", 4);
				free(session_id);
				free(username);
				state = STATE_NORMAL_DONE;
				break;
			}
			case STATE_ACTION_CMD_USER_RESET:{
				// parse session_id user_name
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_USER_NAME 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_USER_NAME;
						} else if (var_state == VAR_STATE_USER_NAME){
							username = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if(strlen(cursor) > 0){
					if(strncasecmp(cursor, "set_face_id", 11) == 0){
						cursor += 11;
						// read face data from rpc_fd
						write(rpc_fd, "<data>", 6);
						uint32_t face_data_size = FACE_DATA_SIZE*sizeof(vec_float);
						face_data = calloc(1, face_data_size+1);
						if(read(rpc_fd, face_data, face_data_size) != face_data_size){
							state = STATE_NORMAL_ERROR;
						}
						reset_face_id = 1;
					}
				}
				//printf("[STATE_ACTION_CMD_USER_RESET] session_id: %s,"
				//	" username: %s set_face_id: %d\n", session_id, username, reset_face_id);
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_USER_RESET;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_RESET:{
				if(!session_id || !username){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				if(reset_face_id){
					op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
					op.params[0].tmpref.buffer = session_id;
					op.params[0].tmpref.size = strlen(session_id);
					op.params[1].tmpref.buffer = username;
					op.params[1].tmpref.size = strlen(session_id);
					op.params[2].tmpref.buffer = face_data;
					op.params[2].tmpref.size = FACE_DATA_SIZE*sizeof(vec_float);
				} else{
					op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
					op.params[0].tmpref.buffer = session_id;
					op.params[0].tmpref.size = strlen(session_id);
					op.params[1].tmpref.buffer = username;
					op.params[1].tmpref.size = strlen(session_id);
				}
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_RESET, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(username);
					state = STATE_NORMAL_ERROR;
					break;
				}
				state = STATE_ACTION_CMD_DO_USER_RESET_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_RESET_DONE:{
				write(rpc_fd, "<ok>", 4);
				free(session_id);
				free(username);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_ENABLE:{
				// parse session_id user_name
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_USER_NAME 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_USER_NAME;
						} else if (var_state == VAR_STATE_USER_NAME){
							username = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				//printf("[STATE_ACTION_CMD_USER_ENABLE] session_id: %s,"
				//	" user_name: %s\n", session_id, username);
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_USER_ENABLE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_ENABLE:{
				if(!session_id || !username){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = username;
				op.params[1].tmpref.size = strlen(username);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_ENABLE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(username);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				free(username);
				state = STATE_ACTION_CMD_DO_USER_ENABLE_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_ENABLE_DONE:{
				write(rpc_fd, "<ok>", 6);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_CMD_USER_DISABLE:{
				// parse session_id user_name
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_USER_NAME 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_USER_NAME;
						} else if (var_state == VAR_STATE_USER_NAME){
							username = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				//printf("[STATE_ACTION_CMD_USER_DISABLE] session_id: %s,"
				//	" user_name: %s\n", session_id, username);
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_CMD_DO_USER_DISABLE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_DISABLE:{
				if(!session_id || !username){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = username;
				op.params[1].tmpref.size = strlen(username);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_USER_DISABLE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(username);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				free(username);
				state = STATE_ACTION_CMD_DO_USER_DISABLE_DONE;
				break;
			}
			case STATE_ACTION_CMD_DO_USER_DISABLE_DONE:{
				write(rpc_fd, "<ok>", 6);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_CREATE_FILE:{
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_PARENT_ID 1
				#define VAR_STATE_FILENAME 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							//printf("[STATE_ACTION_SECFS_CREATE_FILE] session_id: %s", session_id);
							var_state = VAR_STATE_PARENT_ID;
						} else if (var_state == VAR_STATE_PARENT_ID){
							parent_id = strtol(argn_start, NULL, 10);
							//printf("[STATE_ACTION_SECFS_CREATE_FILE] parent_id: %d", parent_id);
							var_state = VAR_STATE_FILENAME;
						}
						else if (var_state == VAR_STATE_FILENAME){
							filename = strdup(argn_start);
							//printf("[STATE_ACTION_SECFS_CREATE_FILE] filename: %s", filename);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				// read file data
				write(rpc_fd, "<data>", 6);
				file_data = calloc(MAX_FILE_DATA, 1);
				if((file_data_sz = recv(rpc_fd, file_data, MAX_FILE_DATA, 0)) < 0){
					free(session_id);
					free(filename);
					free(file_data);
					state = STATE_NORMAL_ERROR;
					break;
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_CREATE_FILE;
				break;
			}
			case STATE_ACTION_SECFS_DO_CREATE_FILE:{
				if(!session_id || !filename || !file_data){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INOUT);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = filename;
				op.params[1].tmpref.size = strlen(filename);
				op.params[2].tmpref.buffer = file_data;
				op.params[2].tmpref.size = file_data_sz;
				op.params[3].value.a = parent_id;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_CREATE_SEC_FILE, &op, NULL);
				if (res == TEEC_ERROR_ACCESS_CONFLICT){
					free(session_id);
					free(filename);
					free(file_data);
					write(rpc_fd, "<conflict>", 10);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res == TEEC_ERROR_STORAGE_NOT_AVAILABLE){
					free(session_id);
					free(filename);
					free(file_data);
					write(rpc_fd, "<nospace>", 9);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(filename);
					free(file_data);
					state = STATE_NORMAL_ERROR;
					break;
				}
				ext_id_out = op.params[3].value.b;
				free(session_id);
				free(filename);
				free(file_data);
				state = STATE_ACTION_SECFS_DO_CREATE_FILE_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_CREATE_FILE_DONE:{
				if(ext_id_out != ~0){
					char *out = NULL;
					asprintf(&out, "<ext_id:%u>", ext_id_out);
					write(rpc_fd, out, strlen(out));
					free(out);
				} else{
					write(rpc_fd, "<ok>", 4);
				}			
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_UPDATE_FILE:{
				// parse session_id, ext_id and file_data
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				write(rpc_fd, "<data>", 6);
				file_data = calloc(MAX_FILE_DATA, 1);
				if((file_data_sz = recv(rpc_fd, file_data, MAX_FILE_DATA, 0)) < 0){
					free(session_id);
					free(file_data);
					state = STATE_NORMAL_ERROR;
					break;
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_UPDATE_FILE;
			}
			case STATE_ACTION_SECFS_DO_UPDATE_FILE:{
				// TA_D3_CMD_UPDATE_SEC_FILE
				if(!session_id || !file_data){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[2].tmpref.buffer = file_data;
				op.params[2].tmpref.size = file_data_sz;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_UPDATE_SEC_FILE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(file_data);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				free(file_data);
				state = STATE_ACTION_SECFS_DO_UPDATE_FILE_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_UPDATE_FILE_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_DELETE_FILE:{
				// parse session_id ext_id
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_DEL_MODE 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_DEL_MODE;
						} else if(var_state == VAR_STATE_DEL_MODE){
							if(strlen(argn_start) == 0){
								del_mode = 0;
							} else{
								if(!strcasecmp(argn_start, "erase"))
									del_mode = 1;
								else if(!strcasecmp(argn_start, "mark"))
									del_mode = 0;
								else{
									state = STATE_NORMAL_ERROR;
								}
							}
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_DELETE_FILE;
				break;
			}
			case STATE_ACTION_SECFS_DO_DELETE_FILE:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[1].value.b = del_mode;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_DELETE_SEC_FILE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				state = STATE_ACTION_SECFS_DO_DELETE_FILE_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_DELETE_FILE_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_FILE_INFO:{
				// parse session_id ext_id
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_FILE_INFO;
				break;
			}
			case STATE_ACTION_SECFS_DO_FILE_INFO:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				file_info_t file_info;
				memset(&op, 0, sizeof(op));
				memset(&file_info, 0, sizeof(file_info_t));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[2].tmpref.buffer = &file_info;
				op.params[2].tmpref.size = sizeof(file_info_t);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_GET_SEC_FILE_INFO, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// write file info
				if(op.params[2].tmpref.size == sizeof(file_info_t)){
					write(rpc_fd, &file_info, sizeof(file_info_t));
					free(session_id);
					state = STATE_ACTION_SECFS_DO_FILE_INFO_DONE;
					break;
				} else{
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
			}
			case STATE_ACTION_SECFS_DO_FILE_INFO_DONE:{
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_READ_FILE:{
				// parse session_id and ext_id
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				if(strlen(cursor) > 0){
					max_read_sz = strtol(cursor, NULL, 10);
				}
				if(max_read_sz == 0){
					max_read_sz = MAX_FILE_DATA;
				} else{
					max_read_sz = max_read_sz > MAX_FILE_DATA? MAX_FILE_DATA: max_read_sz;
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_READ_FILE;
				break;
			}
			case STATE_ACTION_SECFS_DO_READ_FILE:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[2].tmpref.buffer = calloc(max_read_sz+1, 1);
				op.params[2].tmpref.size = max_read_sz;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_READ_SEC_FILE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// write data size num
				file_data_sz = op.params[2].tmpref.size;
				if(file_data_sz <= max_read_sz){
					char *out = NULL;
					asprintf(&out, "%d", file_data_sz);
					write(rpc_fd, out, strlen(out));
					if(out) free(out);
					if(recv(rpc_fd, reqbuf, 1024, 0) < 0){
						free(session_id);
						free(op.params[2].tmpref.buffer);
						state = STATE_NORMAL_ERROR;
						break;
					}
					if(strncasecmp(reqbuf, "<data>", 6) != 0){
						free(session_id);
						free(op.params[2].tmpref.buffer);
						state = STATE_NORMAL_ERROR;
						break;
					}
					// write data
					write(rpc_fd, op.params[2].tmpref.buffer, file_data_sz);
					free(session_id);
					free(op.params[2].tmpref.buffer);
					state = STATE_ACTION_SECFS_DO_READ_FILE_DONE;
					break;
				} else{
					free(session_id);
					free(op.params[2].tmpref.buffer);
					state = STATE_NORMAL_ERROR;
					break;
				}
			}
			case STATE_ACTION_SECFS_DO_READ_FILE_DONE:{
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_RENAME_FILE:{
				// parse session_id, ext_id and new_filename
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_NEW_NAME 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_NEW_NAME;
						} else if (var_state == VAR_STATE_NEW_NAME){
							new_filename = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_RENAME_FILE;
				break;
			}
			case STATE_ACTION_SECFS_DO_RENAME_FILE:{
				if(!session_id || !new_filename){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[2].tmpref.buffer = new_filename;
				op.params[2].tmpref.size = strlen(new_filename);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_RENAME_SEC_FILE, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(new_filename);
					state = STATE_NORMAL_ERROR;
					break;
				}
				free(session_id);
				free(new_filename);
				state = STATE_ACTION_SECFS_DO_RENAME_FILE_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_RENAME_FILE_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_SLOTS_INFO:{
				// parse session_id
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_STOP 1
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						} 
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_SLOTS_INFO;
				break;
			}
			case STATE_ACTION_SECFS_DO_SLOTS_INFO:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = calloc(MAX_FILE_COUNT*sizeof(uint8_t), 1);
				op.params[1].tmpref.size = MAX_FILE_COUNT*sizeof(uint8_t);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_GET_SECFS_SLOTS_INFO, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// write slot data
				write(rpc_fd, op.params[1].tmpref.buffer, op.params[1].tmpref.size);
				free(session_id);
				free(op.params[1].tmpref.buffer);
				state = STATE_ACTION_SECFS_DO_SLOTS_INFO_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_SLOTS_INFO_DONE:{
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_CREATE_DIR:{
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_PARENT_ID 1
				#define VAR_STATE_DIR_NAME 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_PARENT_ID;
						} else if (var_state == VAR_STATE_PARENT_ID){
							parent_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_DIR_NAME;
						} else if (var_state == VAR_STATE_DIR_NAME){
							dir_name = strdup(argn_start);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_CREATE_DIR;
				break;
			}
			case STATE_ACTION_SECFS_DO_CREATE_DIR:{
				if(!session_id || !dir_name){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_VALUE_OUTPUT);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].tmpref.buffer = dir_name;
				op.params[1].tmpref.size = strlen(dir_name);
				op.params[2].value.a = parent_id;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_CREATE_SEC_DIR, &op, NULL);
				if (res == TEEC_ERROR_ACCESS_CONFLICT){
					free(session_id);
					free(dir_name);
					write(rpc_fd, "<conflict>", 10);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res == TEEC_ERROR_STORAGE_NOT_AVAILABLE){
					free(session_id);
					free(dir_name);
					write(rpc_fd, "<nospace>", 9);
					state = STATE_NORMAL_DONE;
					break;
				}
				if (res != TEEC_SUCCESS){
					free(session_id);
					free(dir_name);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// success
				ext_id_out = op.params[3].value.a;
				free(session_id);
				free(dir_name);
				state = STATE_ACTION_SECFS_DO_CREATE_DIR_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_CREATE_DIR_DONE:{
				if(ext_id_out != ~0){
					char *out = NULL;
					asprintf(&out, "<ext_id:%d>", ext_id_out);
					write(rpc_fd, out, strlen(out));
					free(out);
				} else{
					write(rpc_fd, "<ok>", 4);
				}
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_DELETE_DIR:{
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_RM_MODE 2
				#define VAR_STATE_STOP 3
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_RM_MODE;
						} else if (var_state == VAR_STATE_RM_MODE){
							if(!strncasecmp(argn_start, "nonrecur", 8)){
								rm_mode = 0;
							} else if(!strncasecmp(argn_start, "recur", 5)){
								rm_mode = 1;
							} else{
								state = STATE_NORMAL_ERROR;
								break;
							}
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_DELETE_DIR;
				break;
			}
			case STATE_ACTION_SECFS_DO_DELETE_DIR:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				memset(&op, 0, sizeof(op));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_NONE, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[1].value.b = rm_mode;
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_DELETE_SEC_DIR, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// success
				free(session_id);
				state = STATE_ACTION_SECFS_DO_DELETE_DIR_DONE;
				break;
			}
			case STATE_ACTION_SECFS_DO_DELETE_DIR_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_ACTION_SECFS_DIR_INFO:{
				#define VAR_STATE_SESSION_ID 0
				#define VAR_STATE_EXT_ID 1
				#define VAR_STATE_STOP 2
				var_state = VAR_STATE_SESSION_ID;
				while(var_state != VAR_STATE_STOP){
					while(*cursor == ' ' || *cursor == '\t')
						cursor++;
					if(!(strlen(cursor) > 0)){
						state = STATE_NORMAL_ERROR;
						break;
					} else{
						char *argn_start = cursor;
						while(*cursor != ' ' && *cursor != '\t' && *cursor != '\0')
							cursor++;
						if (*cursor != '\0'){
							*cursor = '\0';
							cursor++;
						}
						if (var_state == VAR_STATE_SESSION_ID){
							session_id = strdup(argn_start);
							var_state = VAR_STATE_EXT_ID;
						} else if (var_state == VAR_STATE_EXT_ID){
							ext_id = strtol(argn_start, NULL, 10);
							var_state = VAR_STATE_STOP;
						}
					}
				}
				if (state == STATE_NORMAL_ERROR)
					break;
				state = STATE_ACTION_SECFS_DO_DIR_INFO;
				break;
			}
			case STATE_ACTION_SECFS_DO_DIR_INFO:{
				if(!session_id){
					state = STATE_NORMAL_ERROR;
					break;
				}
				TEEC_Result res;
				TEEC_Operation op;
				dir_info_t dir_info;
				memset(&op, 0, sizeof(op));
				memset(&dir_info, 0, sizeof(dir_info_t));
				op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_VALUE_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE);
				op.params[0].tmpref.buffer = session_id;
				op.params[0].tmpref.size = strlen(session_id);
				op.params[1].value.a = ext_id;
				op.params[2].tmpref.buffer = &dir_info;
				op.params[2].tmpref.size = sizeof(dir_info_t);
				res = TEEC_InvokeCommand(&sess, TA_D3_CMD_GET_SEC_DIR_INFO, &op, NULL);
				if (res != TEEC_SUCCESS){
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
				// write dir info
				if(op.params[2].tmpref.size == sizeof(dir_info_t)){
					write(rpc_fd, &dir_info, sizeof(dir_info_t));
					free(session_id);
					state = STATE_ACTION_SECFS_DO_DIR_INFO_DONE;
					break;
				} else{
					free(session_id);
					state = STATE_NORMAL_ERROR;
					break;
				}
			}
			case STATE_ACTION_SECFS_DO_DIR_INFO_DONE:{
				write(rpc_fd, "<ok>", 4);
				state = STATE_NORMAL_DONE;
				break;
			}
			// ================================================================
			case STATE_NORMAL_DONE:{
				return 0;
			}
			case STATE_NORMAL_ERROR:{
				write(rpc_fd, "<error>", 7);
				return 1;
			}
			default:{
				state = STATE_NORMAL_ERROR;
				fprintf(stderr, "Parse RPC packet fail!\n");
				return 1;
			}
		}
	}
	return 0;
}

// handle signal and release resources
void sig_handler(int signo) {
	if (signo == SIGINT) {
		fprintf(stderr, "Received SIGINT\n");
		// release tee session
		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		unlink("/var/run/d3_trusted_core.sock");
		unlink("/var/run/optee_d3_trusted_core.pid");
		exit(0);
	}
	if (signo == SIGCHLD) {
		int status;
		wait(&status);
	}
}

int handle_client(int rpc_fd){
	char *reqbuf = global_buf;
	
	if(test_mode){
		memset(reqbuf, 0, MAX_BUF_SIZE);
	}

	int recv_size = recv(rpc_fd, reqbuf, MAX_BUF_SIZE, 0);
	if(recv_size <= 0){
		perror("recv()");
		return -1;
	}
	fprintf(stderr, "[%d] RPC packet: %s\n", getpid(), reqbuf);

	return parse_rpc_packet(rpc_fd, reqbuf);
}

int server_loop(void) {
	// listen on unix:/var/run/d3_trusted_core.sock
	int sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock_fd < 0) {
		perror("socket() failed!\n");
		return 1;
	}
	int enable = 0;
	if (setsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &enable, sizeof(enable)) == -1) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	unlink("/var/run/d3_trusted_core.sock");

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, "/var/run/d3_trusted_core.sock", sizeof(addr.sun_path)-1);
	if (bind(sock_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("bind() failed!\n");
		return 1;
	}
	if (listen(sock_fd, 4) == -1) {
		perror("listen() failed!\n");
		return 1;
	}
	chmod("/var/run/d3_trusted_core.sock", 0766);
	printf("Listening on unix:/var/run/d3_trusted_core.sock\n");

	while (1) {
		int rpc_fd = accept(sock_fd, NULL, NULL);
		if (rpc_fd == -1) {
			perror("accept() failed!\n");
			return 1;
		}
		int pid;
		if(test_mode){
			pid = 0;
		} else{
			pid = fork();
		}
		if(pid < 0){
			perror("fork() failed!\n");
			close(rpc_fd);
			continue;
		}
		if (pid == 0) {
			// child
			fprintf(stderr, "[%d] Accepted RPC Client\n", getpid());
			if(!test_mode)
				close(sock_fd);
			handle_client(rpc_fd);
			fprintf(stderr, "[%d] RPC Client Disconnected\n", getpid());
			close(rpc_fd);
			if(!test_mode)
				exit(0);
		} else if (pid > 0) {
			close(rpc_fd);
		}
	}
	return 0;
}

int init_daemon(int argc, char *argv[]){
        // ignore I/O signal and STOP signal
        signal(SIGTTOU,SIG_IGN);
        signal(SIGTTIN,SIG_IGN);
        signal(SIGTSTP,SIG_IGN);
        signal(SIGHUP,SIG_IGN);

        int pid = fork();
        if (pid < 0) {
			perror("fork() failed!\n");
            exit(-1);
        }
        if (pid > 0) {
            exit(0); 
        }

        // new process group
        setsid(); 

        pid = fork();
        if (pid < 0) {
            perror("fork() failed!\n");
        }
        if (pid > 0) {
            exit(0);
        }

        // redirect log message
		if(argc > 2 && argv[2] != NULL){
			// open and create
			int fd1 = open(argv[2], O_RDWR | O_CREAT, 0666);
			if(fd1 > 0){
				dup2(fd1, stdout->_fileno);
				dup2(fd1, stderr->_fileno);
				close(fd1);
			} else{
				fprintf(stderr, "[%d] Can not open log file '%s'!\n", getpid(), argv[2]);
				exit(-1);
			}
		}

		// no stdin !!!
		int fd2 = open("/dev/null", O_WRONLY);
		if(fd2 > 0){
			dup2(fd2, stdin->_fileno);
			close(fd2);
		} else{
			close(stdin->_fileno);
		}
        
        umask(0);

		fprintf(stderr, "[%d] Optee_d3_trusted_core service started!\n", getpid());

        return 0;
}

int calc_sha256_in_ta(uint8_t *data, uint32_t data_sz, uint8_t *hash_out){
	TEEC_Operation op;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = data;
	op.params[0].tmpref.size = data_sz;
	op.params[1].tmpref.buffer = hash_out;
	op.params[1].tmpref.size = TEE_SHA256_HASH_SIZE;
	if (TEEC_InvokeCommand(&sess, TA_D3_CMD_CALC_SHA256, &op, NULL) != TEEC_SUCCESS){
		return 1;
	} else{
		return 0;
	}
}

int init_core_files(){
	memset(core_files_sha256, 0, sizeof(core_files_sha256));
	char *core_file = NULL;
	for(int i = 0; core_files[i] != NULL; i++){
		core_file = core_files[i];
		fprintf(stderr, "[%d] Calc sha256 of core file: '%s'...\n", getpid(), core_file);
		int fd = open(core_file, O_RDONLY);
		if(fd < 0){
			return 1;
		}
		struct stat st;
		if(fstat(fd, &st) < 0){
			close(fd);
			return 1;
		}
		uint8_t *file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(file_data == MAP_FAILED){
			close(fd);
			return 1;
		}
		if(calc_sha256_in_ta(file_data, st.st_size, core_files_sha256[i]) != 0){
			munmap(file_data, st.st_size);
			close(fd);
			return 1;
		}
		munmap(file_data, st.st_size);
		close(fd);
	}
	return 0;
}

int check_core_files(){
	char *core_file = NULL;
	char tmp_hash[TEE_SHA256_HASH_SIZE] = {0};
	for(int i = 0; core_files[i] != NULL; i++){
		core_file = core_files[i];
		fprintf(stderr, "[%d] Check sha256 of core file: '%s'...\n", getpid(), core_file);
		int fd = open(core_file, O_RDONLY);
		if(fd < 0){
			return 1;
		}
		struct stat st;
		if(fstat(fd, &st) < 0){
			close(fd);
			return 1;
		}
		uint8_t *file_data = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
		if(file_data == MAP_FAILED){
			close(fd);
			return 1;
		}
		if(calc_sha256_in_ta(file_data, st.st_size, tmp_hash) != 0){
			munmap(file_data, st.st_size);
			close(fd);
			return 1;
		}
		munmap(file_data, st.st_size);
		close(fd);
		if(memcmp(tmp_hash, core_files_sha256[i], TEE_SHA256_HASH_SIZE) != 0){
			fprintf(stderr, "[%d] Core file '%s' has been modified!\n", getpid(), core_file);
			return 1;
		}
	}
	return 0;
}

int main(int argc, char *argv[], char *envp[]){
	TEEC_Result res;
	uint32_t err_origin;

	if(argc > 1){
		if(strcmp(argv[1], "daemon") == 0){
			init_daemon(argc, argv);
		} else if(strcmp(argv[1], "test") == 0){
			test_mode = 1;
		}
	}

	FILE *fp = fopen("/var/run/optee_d3_trusted_core.pid", "w");
	if(fp != NULL){
		fprintf(fp, "%d", getpid());
		fclose(fp);
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InitializeContext failed with code 0x%x\n", res);
		return 1;
	}
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_OpenSession failed with code 0x%x origin 0x%x\n", res, err_origin);
		return 1;
	}

	if(init_core_files() != 0){
		fprintf(stderr, "[%d] init_core_files() failed!\n", getpid());
		return 1;
	}

	// set signal handler
	if (signal(SIGINT, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Can't handle SIGINT\n");
		return 1;
	}
	if (signal(SIGCHLD, sig_handler) == SIG_ERR) {
		fprintf(stderr, "Can't handle SIGCHLD\n");
		return 1;
	}

	// start server loop
	return server_loop();
}
