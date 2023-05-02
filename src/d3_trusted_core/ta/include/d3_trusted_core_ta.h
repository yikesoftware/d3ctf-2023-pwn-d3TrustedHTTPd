/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef TA_D3_TRUSTED_CORE_H
#define TA_D3_TRUSTED_CORE_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
// ae13ed5a-4d7a-47b6-81f1-20cd2adfb340
#define TA_D3_TRUSTED_CORE_UUID \
	{ 0xae13ed5a, 0x4d7a, 0x47b6, \
		{ 0x81, 0xf1, 0x20, 0xcd, 0x2a, 0xdf, 0xb3, 0x40} }


#define TA_D3_CMD_DEBUG_LOG				0x1000
#define TA_D3_CMD_AUTH_USER_PASSWD 		0x1001
#define TA_D3_CMD_AUTH_USER_FACE_ID		0x1002
#define TA_D3_CMD_AUTH_SESSION_ID 		0x1003

#define TA_D3_CMD_GET_USER_INFO         0x2000
#define TA_D3_CMD_GET_USER_LIST         0x2001

#define TA_D3_CMD_USER_PASSWD 			0x2010
#define TA_D3_CMD_USER_ENABLE 			0x2011
#define TA_D3_CMD_USER_DISABLE 			0x2012
#define TA_D3_CMD_USER_RESET			0x2013

#define TA_D3_CMD_USER_LOGOUT 			0x2020
#define TA_D3_CMD_USER_KICKOUT      	0x2021

#define TA_D3_CMD_CREATE_SEC_FILE         0x3000
#define TA_D3_CMD_DELETE_SEC_FILE         0x3001
#define TA_D3_CMD_READ_SEC_FILE           0x3002
#define TA_D3_CMD_UPDATE_SEC_FILE         0x3003
#define TA_D3_CMD_RENAME_SEC_FILE         0x3004

#define TA_D3_CMD_CREATE_SEC_DIR          0x3010
#define TA_D3_CMD_DELETE_SEC_DIR          0x3011
#define TA_D3_CMD_GET_SEC_FILE_INFO       0x3012
#define TA_D3_CMD_GET_SEC_DIR_INFO        0x3013
#define TA_D3_CMD_GET_SECFS_SLOTS_INFO    0x3020

#define TA_D3_CMD_CHECK_ALIVE         	0x4000
#define TA_D3_CMD_CALC_SHA256         	0x4001

#define TEE_SHA256_HASH_SIZE 32u

#define MAX_USERNAME_LEN 128
#define MIN_PASSWORD_LEN 6
#define MAX_PASSWORD_LEN 128
#define PASSWORD_HASH_SIZE (TEE_SHA256_HASH_SIZE*2)
#define MAX_SESSION_LEN 128
#define HTTP_SESSION_LEN (TEE_SHA256_HASH_SIZE*2)
enum {
	USER_TYPE_ADMIN,
	USER_TYPE_USER,
	USER_TYPE_GUEST,
	USER_TYPE_COUNT
};
enum {
	ACTION_PERMISSON_PASSWD,
	ACTION_PERMISSON_ENABLE,
	ACTION_PERMISSON_DISABLE,
	ACTION_PERMISSON_KICOOUT,
	ACTION_PERMISSON_RESET,
	ACTION_PERMISSON_CREATE_FILE,
	ACTION_PERMISSON_DELETE_FILE,
	ACTION_PERMISSON_CREATE_DIR,
	ACTION_PERMISSON_DELETE_DIR,
	ACTION_PERMISSON_READ_FILE,
	ACTION_PERMISSON_WRITE_FILE,
	ACTION_PERMISSON_LIST_FILE,
	ACTION_COUNT
};
static uint8_t admin_permission_table[USER_TYPE_COUNT][ACTION_COUNT];
static uint8_t user_permission_table[USER_TYPE_COUNT][ACTION_COUNT];
static uint8_t guest_permission_table[USER_TYPE_COUNT][ACTION_COUNT];
static const char *user_type_table[USER_TYPE_COUNT+1] = {
	"admin",
	"user",
	"guest",
	0
};
#define USER_MAGIC_NORMAL 0x72657375
#define USER_MAGIC_DISABLED 0xffffffff 
typedef struct UserInfo user_info_t;
struct UserInfo{
	uint32_t magic;
	uint32_t uid;
	uint32_t type;
	uint32_t face_id;
	char username[MAX_USERNAME_LEN+8];
	char password[MAX_PASSWORD_LEN+8];
	uint32_t face_id_expired_round;
	double *face_data;
	user_info_t *next;
};
typedef struct UserInfoOut user_info_out_t;
struct UserInfoOut{
	// public regions
	uint32_t magic;
	uint32_t uid;
	uint32_t type;
	uint32_t face_id;
	char username[MAX_USERNAME_LEN+8];
};

#define FILE_NODE_EMPTY 0x1
#define FILE_NODE_DIR 0x2
#define FILE_NODE_FILE 0x4
#define FILE_NODE_DEL 0xff
#define OBJ_ID_SIZE TEE_SHA256_HASH_SIZE*2

typedef struct FileNode file_node_t;
struct FileNode{
	uint32_t node_type;
	uint32_t parent_id;
	uint32_t ext_id;
	uint32_t owner;
	uint32_t file_size;
	char obj_id[OBJ_ID_SIZE];
};

#define MAKE_FILE_NODE_FILE(node, _parent_id, _ext_id, _owner, _file_sz, _obj_id) ({ \
	int _ret = 0; 									\
	(node).node_type = FILE_NODE_FILE;				\
	(node).parent_id = _parent_id;					\
	(node).ext_id = _ext_id;						\
	(node).owner = _owner;							\
	(node).file_size = _file_sz;					\
	memcpy(node.obj_id, _obj_id, OBJ_ID_SIZE); 		\
	_ret;											\
})
#define MAKE_FILE_NODE_DIR(node, _parent_id, _ext_id, _owner, _obj_id) ({ \
	int _ret = 0; 									\
	(node).node_type = FILE_NODE_DIR;				\
	(node).parent_id = _parent_id;					\
	(node).ext_id = _ext_id;							\
	(node).owner = _owner;							\
	(node).file_size = 0;							\
	memcpy(node.obj_id, _obj_id, OBJ_ID_SIZE); 		\
	_ret;											\
})

#define MAKE_FILE_NODE_EMPTY(node) ({ 				\
	int _ret = 0; 									\
	memset(&(node), 0, sizeof(file_node_t));		\
	(node).node_type = FILE_NODE_EMPTY;				\
	_ret;											\
})

#define MAX_FILE_COUNT 128
#define MAX_FILE_ID MAX_FILE_COUNT
#define MAX_FILE_NAME 128
#define MAX_DIR_NAME MAX_FILE_NAME
#define MAX_FILE_DATA 4096
#define SEC_FILE_STATUS_FILE 0xffff1000
#define SEC_FILE_STATUS_DIR 0xffff1001
#define SEC_FILE_STATUS_DEL 0xffffffff


typedef struct SecFile sec_file_t;
typedef sec_file_t sec_dir_t;
#pragma pack(push, 4)
struct SecFile{
	uint32_t magic;
	char hash[TEE_SHA256_HASH_SIZE];
	uint32_t name_size;
	uint32_t data_size;
	char filename[MAX_FILE_NAME];
	uint32_t status;
	char data[0];
};
#pragma pack(pop)


typedef struct FileInfo file_info_t;
struct FileInfo{
	uint32_t magic; 
	uint32_t node_type;
	uint32_t parent_id;
	uint32_t ext_id;
	uint32_t owner;
	uint32_t file_size; 
	char filename[MAX_FILE_NAME];
	char hash[TEE_SHA256_HASH_SIZE*2];
};

typedef struct DirInfo dir_info_t;
struct DirInfo{
	uint32_t magic;
	uint32_t node_type;
	uint32_t parent_id;
	uint32_t ext_id;
	uint32_t owner;
	char dir_name[MAX_FILE_NAME];
	uint8_t sub_items[MAX_FILE_COUNT];
};

#define MAKE_FILE_INFO_DETAIL_REF(file_info, file_node, _filename) ({ 		\
	if(_file_info){ 														\
		(_file_info)->node_type = (file_node)->node_type; 					\
		(_file_info)->parent_id = (file_node)->parent_id; 					\
		(_file_info)->ext_id = (file_node)->ext_id; 						\
		(_file_info)->owner = (file_node)->owner; 							\
		(_file_info)->file_size = (file_node)->file_size; 					\
		strncpy((_file_info)->filename, _filename, MAX_FILE_NAME);			\
	} 																		\
	_file_info; 															\
})

#define SEC_FILE_MAGIC 0x73656366 
#define MAKE_SEC_FILE_REF(file, _filename, data, data_sz) ({ 					\
    int _ret = 0;																\
	if(strlen(_filename) > MAX_FILE_NAME)										\
		_ret = 1;																\
	if(d3_core_sha256(data, data_sz, (file)->hash) != TEE_SHA256_HASH_SIZE) 	\
		_ret = 1;																\
	(file)->magic = SEC_FILE_MAGIC;												\
	memset((file)->filename, 0, MAX_FILE_NAME);									\
	strncpy((file)->filename, _filename, MAX_FILE_NAME);						\
	(file)->status = SEC_FILE_STATUS_FILE;										\
	memcpy((file)->data, data, data_sz);										\
	(file)->name_size = strlen((file)->filename);								\
	(file)->data_size = data_sz;												\
	_ret;																		\
})

#define MAKE_SEC_DIR_REF(file, _dir_name) ({ 									\
    int _ret = 0;																\
	if(strlen(_dir_name) > MAX_FILE_NAME)										\
		_ret = 1;																\
	memset((file)->hash, 0, TEE_SHA256_HASH_SIZE);								\
	(file)->magic = SEC_FILE_MAGIC;												\
	memset((file)->filename, 0, MAX_FILE_NAME);									\
	strncpy((file)->filename, _dir_name, MAX_FILE_NAME);						\
	(file)->name_size = strlen((file)->filename);								\
	(file)->data_size = 0;														\
	(file)->status = SEC_FILE_STATUS_DIR;									    \
	_ret;																		\
})


#define MAKE_USER_INFO_OUT(user_info, user_info_out) { 	\
	user_info_out.magic = user_info.magic; 				\
	user_info_out.uid = user_info.uid; 					\
	user_info_out.type = user_info.type; 				\
	user_info_out.face_id = user_info.face_id; 			\
	memcpy(user_info_out.username, user_info.username, MAX_USERNAME_LEN+8); \
}

#define MAKE_USER_INFO_OUT_REF(user_info, user_info_out) { 	\
	(user_info_out)->magic = (user_info)->magic; 				\
	(user_info_out)->uid = (user_info)->uid; 					\
	(user_info_out)->type = (user_info)->type; 					\
	(user_info_out)->face_id = (user_info)->face_id; 			\
	memcpy((user_info_out)->username, (user_info)->username, MAX_USERNAME_LEN+8); \
}

typedef struct Session session_t;
struct Session{
	uint32_t uid;
	user_info_t *user_info;
	char session_id[MAX_SESSION_LEN+8];
	session_t *next;
};


// all functions's declaration
typedef double vec_float;
vec_float sqrt(vec_float  x);
vec_float d3_core_euclidean_distance(const vec_float *x, const vec_float *y, uint32_t size);
uint32_t d3_core_sha256(uint8_t * data, uint32_t data_len, uint8_t* hash);
uint32_t d3_core_hexlify(uint8_t *data, uint32_t data_len, uint8_t *hex_str, uint32_t hex_str_len);
uint32_t d3_core_unhexlify(uint8_t *hex_str, uint32_t hex_str_len, uint8_t *data, uint32_t data_len);
uint32_t d3_core_sha256_and_hexlify(uint8_t * data, uint32_t data_len, uint8_t* hash_hexlify, uint32_t hash_hexlify_len);
uint32_t d3_core_add_user_info(user_info_t **entry, uint32_t magic, uint32_t user_id, uint32_t user_type, const char * username, const char * password);
void d3_core_log_user_obj(user_info_t *entry);
uint32_t d3_core_remove_user_info(user_info_t **entry, const char * username);
session_t *d3_core_get_session(session_t *entry, const char *session_id);
session_t *d3_core_get_alive_session_by_uid(session_t *entry, uint32_t uid);
session_t *d3_core_get_alive_session_by_name(session_t *entry, const char *username);
uint32_t d3_core_check_valid_session(session_t *entry, const char *session_id, session_t **target);
uint32_t d3_core_get_user_info_from_session(session_t *entry, char *session_id, user_info_t **user_info);
uint32_t d3_core_get_user_list(user_info_t *entry, uint32_t *count, user_info_out_t **res);
uint32_t d3_core_enable_user_face_id(user_info_t *entry, const char *username, const vec_float *face_data, uint32_t do_alloc);
uint32_t d3_core_disable_user_face_id(user_info_t *entry, const char *username);
uint32_t d3_core_check_user_passwd(user_info_t *entry, const char *username, const char *password);
uint32_t d3_core_check_user_action_perm(user_info_t *user, user_info_t *op_user, uint32_t action);
uint32_t d3_core_check_user_face(user_info_t *entry, const char *username, const double *face_data, vec_float *similarity);
user_info_t *d3_core_get_user_by_name(user_info_t *entry, const char *username);
user_info_t *d3_core_move_user_by_name(user_info_t **entry_from, user_info_t **entry_to, const char *username);
uint32_t d3_core_add_new_session(session_t **entry, user_info_t *user, const char *session_id);
uint32_t d3_core_delete_session(session_t **entry, const char *session_id);
uint32_t d3_core_kickout_user(session_t **entry, user_info_t *user);

uint32_t d3_core_gen_random_obj_id(char *buf, uint32_t buf_size);
uint32_t d3_core_create_secure_file(const char *filename, uint32_t parent_id, uint32_t owner, const uint8_t *data, uint32_t data_sz, uint32_t *ext_id_out);
uint32_t d3_core_create_secure_dir(const char *dir_name, uint32_t parent_id, uint32_t owner, uint32_t *ext_id_out);
uint32_t d3_core_delete_secure_file(uint32_t ext_id, uint32_t erase);
uint32_t d3_core_delete_secure_dir(uint32_t ext_id, uint32_t recursive);
uint32_t d3_core_get_sec_file_info(uint32_t ext_id, file_info_t *file_info);
uint32_t d3_core_read_sec_file(uint32_t ext_id, char *file_data, uint32_t max_sz, uint32_t *data_sz);


#endif /*TA_D3_TRUSTED_CORE_H*/
