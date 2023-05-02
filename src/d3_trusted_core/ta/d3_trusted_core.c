/*
 * Copyright (c) 2016, Linaro Limited
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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <d3_trusted_core_ta.h>
#include <string.h>

#define FACE_DATA_SIZE 128

#define FACE_DATA_SIZE_BYTES (FACE_DATA_SIZE * sizeof(vec_float))

#define FACE_SIMILARITY_THRESHOLD 0.85
#define FACE_ID_EXPIRED_ROUND 200000

/*static vec_float face_data_eqqie[FACE_DATA_SIZE] = 
	{-0.11221785098314285, 0.030968042090535164, 0.03228399530053139, -0.016970319673419,
	-0.08356742560863495, -0.048710644245147705, -0.06924152374267578, -0.15453746914863586,
	0.07345157116651535, -0.03097793087363243, 0.2738777995109558, -0.029637282714247704,
	-0.16531607508659363, -0.12568823993206024, -0.05169608071446419, 0.15561874210834503,
	-0.1633121371269226, -0.10528454929590225, -0.0262118149548769, 0.0233946330845356,
	0.11273238807916641, -0.0021310693118721247, 0.02570214681327343, 0.027860218659043312,
	-0.13023391366004944, -0.34529581665992737, -0.07585153728723526, -0.09895170480012894,
	0.07138224691152573, -0.03241856023669243, -0.03951932117342949, -0.014536491595208645,
	-0.2109336405992508, -0.002641076687723398, 0.033361393958330154, 0.09253192692995071,
	-0.005469856318086386, -0.05628431215882301, 0.17895248532295227, 0.013538329862058163,
	-0.2988229990005493, 0.06063507869839668, -0.01399280410259962, 0.18557879328727722,
	0.22410902380943298, 0.041230782866477966, 0.05164580047130585, -0.16216769814491272,
	0.11601323634386063, -0.13118229806423187, 0.07676055282354355, 0.1461738795042038,
	0.08151765167713165, 0.03457092493772507, -0.039317868649959564, -0.13836078345775604,
	-0.02083386480808258, 0.07609506696462631, -0.16218453645706177, 0.00865670945495367,
	0.09186007082462311, -0.0338992178440094, 0.011204725131392479, -0.10055490583181381,
	0.15604375302791595, 0.05345520004630089, -0.15069139003753662, -0.1722429394721985,
	0.13057860732078552, -0.15888257324695587, -0.04443589970469475, 0.1251511126756668,
	-0.16182595491409302, -0.21380619704723358, -0.33663052320480347, 0.03644336014986038,
	0.4530635476112366, 0.0847771018743515, -0.19444918632507324, -0.018831767141819,
	-0.07903766632080078, 0.01561010256409645, 0.14826881885528564, 0.12840919196605682,
	0.053831618279218674, 0.006853669416159391, -0.08138024806976318, -0.021460937336087227,
	0.24341191351413727, -0.06426441669464111, -0.05643440783023834, 0.21514193713665009,
	-0.043373167514801025, 0.09438303112983704, -0.010710621252655983, 0.11363665759563446,
	-0.03697093948721886, 0.0639236643910408, -0.026734275743365288, 0.0032475239131599665,
	0.0013773401733487844, -0.03213709965348244, 0.05419137328863144, 0.11320152133703232,
	-0.12637652456760406, 0.15393221378326416, 0.009428800083696842, 0.08632482588291168,
	0.04551259055733681, 0.006371977273374796, -0.0857289656996727, -0.0633707270026207,
	0.11928365379571915, -0.24017372727394104, 0.2818159759044647, 0.18188807368278503,
	0.08363165706396103, 0.09826987981796265, 0.1035720631480217, 0.08638662099838257,
	-0.04315595328807831, -0.034929752349853516, -0.21045148372650146, -0.005256700795143843,
	0.024610120803117752, -0.041166797280311584, 0.10000390559434891, 0.007112976163625717};*/


static vec_float face_data_eqqie[FACE_DATA_SIZE] = 
	{-0.07909375429153442, 0.0465780645608902, 0.01734134741127491, 0.019258292391896248,
	-0.08327321708202362, -0.020917769521474838, -0.04304208606481552, -0.13608764111995697,
	0.0765991136431694, -0.05165336653590202, 0.21672187745571136, -0.02366648241877556,
	-0.1302768737077713, -0.10938984900712967, -0.051303621381521225, 0.16547954082489014,
	-0.1689925491809845, -0.09331785142421722, -0.028461800888180733, 0.00623811362311244,
	0.10255204141139984, -0.0015954237896949053, -0.00571214547380805, 0.03518359735608101,
	-0.0956658199429512, -0.3268744945526123, -0.06941995024681091, -0.09461098164319992,
	0.06550043821334839, -0.056780487298965454, -0.02489815652370453, -0.012603987008333206,
	-0.21437954902648926, 0.012166714295744896, -0.005464205984026194, 0.06255411356687546,
	-0.03133934736251831, -0.059607792645692825, 0.1805286705493927, 0.01385482493788004,
	-0.26042261719703674, 0.07241817563772202, -0.022703299298882484, 0.2076699435710907,
	0.21521607041358948, 0.03033357672393322, 0.03808165341615677, -0.1313118189573288,
	0.11609593033790588, -0.1311185359954834, 0.03986663371324539, 0.14532482624053955,
	0.07946774363517761, 0.051855575293302536, -0.08312621712684631, -0.13379056751728058,
	-0.03257176652550697, 0.05678285285830498, -0.13907493650913239, 0.02418854460120201,
	0.08896172791719437, -0.05820579454302788, -0.005266459193080664, -0.11067326366901398,
	0.19147135317325592, 0.04410986229777336, -0.14987686276435852, -0.14900650084018707,
	0.11875823885202408, -0.19223931431770325, -0.03482762724161148, 0.045637186616659164,
	-0.13801783323287964, -0.20960240066051483, -0.32046130299568176, 0.05397442728281021,
	0.38330894708633423, 0.09720222651958466, -0.18498489260673523, -0.0024695659521967173,
	-0.07669736444950104, 0.03859731927514076, 0.12924328446388245, 0.17446836829185486,
	0.033588945865631104, 0.026839066296815872, -0.039846766740083694, -0.014965367503464222,
	0.2243138998746872, -0.063942551612854, -0.02743184193968773, 0.24245940148830414,
	-0.0477103665471077, 0.07041982561349869, -0.027971085160970688, 0.045479871332645416,
	-0.018082763999700546, 0.05839063972234726, -0.00898813921958208, 0.045246973633766174,
	-0.013973227702081203, -0.07604324817657471, 0.06454171240329742, 0.11460810154676437,
	-0.14376914501190186, 0.16979089379310608, -0.012286619283258915, 0.10983966290950775,
	0.07143106311559677, 0.01204290334135294, -0.1205662339925766, -0.0765782967209816,
	0.1479150503873825, -0.21559394896030426, 0.26486900448799133, 0.18648649752140045,
	0.06915367394685745, 0.11218205839395523, 0.11816539615392685, 0.14444679021835327,
	-0.049748554825782776, -0.012096674181520939, -0.23723474144935608, 0.03303072601556778,
	0.05082893744111061, -0.058701224625110626, 0.06283334642648697, 0.014766393229365349,};
	
user_info_t *user_info = NULL;
user_info_t *user_info_disabled = NULL;
session_t *session = NULL;

// secure file system
file_node_t secure_fs[MAX_FILE_COUNT];
uint32_t root_ext_id = 0;

#define _GET_PERMISION_TABLE(user_type) user_type##_permission_table
// translate user_type_int to user_type_str
#define GET_PERMISION_TABLE(type_int) (type_int == USER_TYPE_ADMIN? _GET_PERMISION_TABLE(admin) : type_int == USER_TYPE_USER? _GET_PERMISION_TABLE(user) : _GET_PERMISION_TABLE(guest))

vec_float sqrt(vec_float  x)
{
    vec_float xn = x / 2.0;
    vec_float xn1 = 0.0;
    const vec_float epsilon = 0.0000000000000001;

    while (1) {
        xn1 = (xn + x / xn) / 2.0;
        if (xn - xn1 < epsilon && xn - xn1 > -epsilon)
            break;
        xn = xn1;
    }

    return xn1;
}

vec_float d3_core_euclidean_distance(const vec_float *x, const vec_float *y, uint32_t size){
	// implement like the following python code
	/*
	def euclideanDistance(x, y):
		sum = 0.0
		for i in range(len(x)):
			sum += (x[i] - y[i]) ** 2
		return 1 / (1 + sum ** 0.5)
	*/
	vec_float sum = 0.0;
	for (uint32_t i = 0; i < size; i++){
		sum += (x[i] - y[i]) * (x[i] - y[i]);
	}
	return 1 / (1 + sqrt(sum));
}

uint32_t d3_core_sha256(uint8_t * data, uint32_t data_len, uint8_t* hash) {
    TEE_Result res;
    TEE_OperationHandle op = NULL;
    uint32_t algo = TEE_ALG_SHA256;
    uint32_t mode = TEE_MODE_DIGEST;
    uint32_t max_hash_size = TEE_SHA256_HASH_SIZE;
    uint32_t hash_size = 0;

    if (data == NULL || data_len == 0 || hash == NULL)
        return TEE_ERROR_BAD_PARAMETERS;

    res = TEE_AllocateOperation(&op, algo, mode, 0);
    if (res != TEE_SUCCESS)
        return res;

    res = TEE_DigestDoFinal(op, data, data_len, hash, &max_hash_size);
    if (res != TEE_SUCCESS)
        return res;

    hash_size = max_hash_size;

    TEE_FreeOperation(op);
    return hash_size;
}

uint32_t d3_core_hexlify(uint8_t *data, uint32_t data_len, uint8_t *hex_str, uint32_t hex_str_len) {
	uint32_t i;
	if (data == NULL || data_len == 0 || hex_str == NULL || hex_str_len == 0)
		return 1;
	if (hex_str_len < data_len*2)
		return 1;
	for (i = 0; i < data_len; i++){
		sprintf((char *)hex_str+i*2, "%02x", data[i]);
	}
	return 0;
}

uint32_t d3_core_sha256_and_hexlify(uint8_t * data, uint32_t data_len, uint8_t* hash_hexlify, uint32_t hash_hexlify_len) {
	uint32_t res;
	uint8_t hash[TEE_SHA256_HASH_SIZE+sizeof(size_t)] = {0};
	if (data == NULL || data_len == 0 || hash_hexlify == NULL || hash_hexlify_len == 0)
		return 1;
	res = d3_core_sha256(data, data_len, hash);
	if (res != TEE_SHA256_HASH_SIZE)
		return 1;
	hash_hexlify_len = hash_hexlify_len>TEE_SHA256_HASH_SIZE*2? TEE_SHA256_HASH_SIZE*2:hash_hexlify_len;
	return d3_core_hexlify(hash, TEE_SHA256_HASH_SIZE, hash_hexlify, hash_hexlify_len);
}

uint32_t d3_core_unhexlify(uint8_t *hex_str, uint32_t hex_str_len, uint8_t *data, uint32_t data_len) {
	uint32_t i;
	uint32_t tmp;
	if (data == NULL || data_len == 0 || hex_str == NULL || hex_str_len == 0)
		return 1;
	if (hex_str_len < data_len*2)
		return 1;
	// do not use sscanf here, it is not secure
	for (i = 0; i < data_len; i++){
		tmp = hex_str[i*2];
		if (tmp >= '0' && tmp <= '9')
			tmp = tmp - '0';
		else if (tmp >= 'a' && tmp <= 'f')
			tmp = tmp - 'a' + 10;
		else if (tmp >= 'A' && tmp <= 'F')
			tmp = tmp - 'A' + 10;
		else
			return 1;
		data[i] = tmp << 4;
		tmp = hex_str[i*2+1];
		if (tmp >= '0' && tmp <= '9')
			tmp = tmp - '0';
		else if (tmp >= 'a' && tmp <= 'f')
			tmp = tmp - 'a' + 10;
		else if (tmp >= 'A' && tmp <= 'F')
			tmp = tmp - 'A' + 10;
		else
			return 1;
		data[i] |= tmp;
	}
	return 0;
}

uint32_t d3_core_add_user_info(user_info_t **entry, uint32_t magic, uint32_t user_id, uint32_t user_type, const char * username, const char * password)
{
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || username == NULL || password == NULL)
		return 1;
	// bad username or password
	if (strlen(username) > MAX_USERNAME_LEN || strlen(password)!= PASSWORD_HASH_SIZE)
		return 1;
		
	if (*entry == NULL){
		// create first userinfo
		tmp_user = TEE_Malloc(sizeof(user_info_t), TEE_MALLOC_FILL_ZERO);
		if (tmp_user == NULL)
			return 1;
		memset(tmp_user, 0, sizeof(user_info_t));
		tmp_user->magic = magic;
		tmp_user->uid = user_id;
		tmp_user->type = user_type;
		strncpy(tmp_user->username, username, MAX_USERNAME_LEN);
		strncpy(tmp_user->password, password, MAX_PASSWORD_LEN);
		tmp_user->next = NULL;
		*entry = tmp_user;
		return 0;
	} else{
		// move to the end of the list
		tmp_user = *entry;
		while (tmp_user->next != NULL){
			tmp_user = tmp_user->next;
		}
		// create new userinfo
		tmp_user->next = TEE_Malloc(sizeof(user_info_t), TEE_MALLOC_FILL_ZERO);
		if (tmp_user->next == NULL)
			return 1;
		memset(tmp_user->next, 0, sizeof(user_info_t));
		tmp_user->next->magic = magic;
		tmp_user->next->uid = user_id;
		tmp_user->next->type = user_type;
		strncpy(tmp_user->next->username, username, MAX_USERNAME_LEN);
		strncpy(tmp_user->next->password, password, MAX_PASSWORD_LEN);
		tmp_user->next->next = NULL;
		return 0;
	}
}

/* void d3_core_log_user_obj(user_info_t *entry){
	if(entry == NULL){
		//EMSG("d3_core_log_user_obj: entry is NULL!");
		return;
	}
	user_info_t *tmp_user = entry;
	while(tmp_user){
		//IMSG("[*] d3_core_log_user_obj(%p): user: %s, uid: %d, type: %d, magic: %x", tmp_user, tmp_user->username, tmp_user->uid, tmp_user->type, tmp_user->magic);
		tmp_user = tmp_user->next;
	}
} */

uint32_t d3_core_remove_user_info(user_info_t **entry, const char * username){
	user_info_t *tmp_user = NULL;
	user_info_t *tmp_user_prev = NULL;
	// check if entry is NULL
	if (entry == NULL || username == NULL){
		//EMSG("d3_core_remove_user_info: Can not remove user, entry or username is NULL!");
		return 1;
	}
	// check username
	uint32_t name_size = strlen(username);
	if (name_size > MAX_USERNAME_LEN){
		//EMSG("d3_core_remove_user_info: Can not remove user, username is too long!");
		return 1;
	}
	tmp_user = *entry;
	while (tmp_user){
		// print username
		//IMSG("d3_core_remove_user_info: Cmp username: %s", tmp_user->username);
		if (TEE_MemCompare(tmp_user->username, username, name_size+1) == 0){
			// found user
			if (tmp_user_prev == NULL){
				// first user
				*entry = tmp_user->next;
			} else{
				// not first user
				tmp_user_prev->next = tmp_user->next;
			}
			TEE_Free(tmp_user);
			return 0;
		}
		tmp_user_prev = tmp_user;
		tmp_user = tmp_user->next;
	}
	// user not found
	//EMSG("d3_core_remove_user_info: Can not remove user, user not found!");
	return 1;
}

session_t *d3_core_get_session(session_t *entry, const char *session_id){
	session_t *tmp_session = NULL;
	// check if entry is NULL
	if (entry == NULL || session_id == NULL){
		//EMSG("d3_core_get_session: Can not get session, entry or session_id is NULL!");
		return NULL;
	}
	// check session_size
	uint32_t session_size = strlen(session_id);
	if (session_size > MAX_SESSION_LEN){
		//EMSG("d3_core_get_session: Can not get session, session_id is too long!");
		return NULL;
	}
	tmp_session = entry;
	while (tmp_session){
		// print session id
		//IMSG("d3_core_get_session: Cmp session_id: %s", tmp_session->session_id);
		if (TEE_MemCompare(tmp_session->session_id, session_id, session_size+1) == 0){
			return tmp_session;
		}
		tmp_session = tmp_session->next;
	}
	return NULL;
}

session_t *d3_core_get_alive_session_by_uid(session_t *entry, uint32_t uid){
	session_t *tmp_session = NULL;
	if (entry == NULL){
		//EMSG("d3_core_get_session_by_uid: Can not get session, entry is NULL!");
		return NULL;
	}
	tmp_session = entry;
	while (tmp_session){
		if (tmp_session->user_info->uid == uid){
			return tmp_session;
		}
		tmp_session = tmp_session->next;
	}
	return NULL;
}

session_t *d3_core_get_alive_session_by_name(session_t *entry, const char *username){
	session_t *tmp_session = NULL;
	if (entry == NULL || username == NULL){
		//EMSG("d3_core_get_alive_session_by_name: Can not get session, entry or username is NULL!");
		return NULL;
	}
	uint32_t name_size = strlen(username);
	if (name_size > MAX_USERNAME_LEN){
		//EMSG("d3_core_get_alive_session_by_name: Can not get session, username is too long!");
		return NULL;
	}
	tmp_session = entry;
	while (tmp_session){
		if (TEE_MemCompare(tmp_session->user_info->username, username, name_size+1) == 0){
			return tmp_session;
		}
		tmp_session = tmp_session->next;
	}
	return NULL;
}

uint32_t d3_core_check_valid_session(session_t *entry, const char *session_id, session_t **target){
	session_t *tmp_session = NULL;
	// check if entry is NULL
	if (entry == NULL || session_id == NULL){
		//EMSG("d3_core_check_valid_session: Can not check session, entry or session_id is NULL!");
		return 1;
	}
	// check session_size
	if (strlen(session_id) > HTTP_SESSION_LEN){
		//EMSG("d3_core_check_valid_session: Can not check session, session_id length error (> HTTP_SESSION_LEN)");
		return 2;
	}
	tmp_session = d3_core_get_session(entry, session_id);
	if(tmp_session == NULL){
		//EMSG("d3_core_check_valid_session: Can not get session!");
		return 2;
	}
	if(tmp_session->user_info->magic == USER_MAGIC_NORMAL){
		if(target != NULL){
			*target = tmp_session;
		}
		return 0;
	} else {
		EMSG("User magic error (!= USER_MAGIC_NORMAL)");
		if(tmp_session->user_info->magic == USER_MAGIC_DISABLED){
			return 3;
		}
		return 1;
	}
}

uint32_t d3_core_get_user_info_from_session(session_t *entry, char *session_id, user_info_t **user_info){
	session_t *tmp_session;
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || session_id == NULL || user_info == NULL)
		return 1;
	tmp_session = d3_core_get_session(entry, session_id);
	if(tmp_session == NULL){
		//EMSG("d3_core_get_user_info_from_session: Can not get session!");
		return 1;
	}
	tmp_user = tmp_session->user_info;
	if(tmp_user == NULL){
		//EMSG("d3_core_get_user_info_from_session: user_info is NULL!");
		return 1;
	}
	if(tmp_user->magic != USER_MAGIC_NORMAL){
		EMSG("User magic error (!= USER_MAGIC_NORMAL)");
		return 1;
	}
	*user_info = tmp_user;
	return 0;
}

uint32_t d3_core_get_user_list(user_info_t *entry, uint32_t *count, user_info_out_t **res){
	if(entry == NULL || count == NULL || res == NULL)
		return 1;
	user_info_t *tmp_user = entry;
	user_info_out_t *tmp_res = NULL;
	uint32_t tmp_count = 0;
	while (tmp_user != NULL){
		tmp_count += 1;
		tmp_res = TEE_Realloc(tmp_res, sizeof(user_info_out_t) * tmp_count);
		if(tmp_res == NULL){
			//EMSG("d3_core_get_user_list: Can't realloc memory!");
			return 1;
		}
		//TEE_MemFill(&tmp_res[tmp_count-1], 0, sizeof(user_info_out_t));
		user_info_out_t *vuln_user = &tmp_res[tmp_count-1];
		MAKE_USER_INFO_OUT_REF(tmp_user, vuln_user);
		tmp_user = tmp_user->next;
	}
	*count = tmp_count;
	*res = tmp_res;
	return 0;
}

uint32_t d3_core_enable_user_face_id(user_info_t *entry, const char *username, const vec_float *face_data, uint32_t do_alloc) {
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || username == NULL || face_data == NULL)
		return 1;
	uint32_t name_len = strlen(username);
	uint32_t face_data_len = FACE_DATA_SIZE*sizeof(vec_float);
	// bad username
	if (name_len > MAX_USERNAME_LEN)
		return 1;
	tmp_user = entry;
	while (tmp_user != NULL){
		if (TEE_MemCompare(tmp_user->username, username, name_len+1) == 0 && tmp_user->magic == USER_MAGIC_NORMAL){
			double *face_data_buf = NULL;
			if(do_alloc){
				face_data_buf = (double *)TEE_Malloc(face_data_len+8, TEE_MALLOC_FILL_ZERO);
				TEE_MemMove(face_data_buf, face_data, face_data_len);
			} else{
				face_data_buf = (double *)face_data;
			}
			if (face_data_buf == NULL)
				return 1;
			tmp_user->face_id = 1;
			tmp_user->face_id_expired_round = FACE_ID_EXPIRED_ROUND;
			if(tmp_user->face_data){
				TEE_Free(tmp_user->face_data);
			}
			tmp_user->face_data = face_data_buf;
			return 0;
		}
		tmp_user = tmp_user->next;
	}
	return 1;
}

uint32_t d3_core_disable_user_face_id(user_info_t *entry, const char *username){
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || username == NULL)
		return 1;
	uint32_t name_len = strlen(username);
	// bad username
	if (name_len > MAX_USERNAME_LEN)
		return 1;
	tmp_user = entry;
	while (tmp_user != NULL){
		if (TEE_MemCompare(tmp_user->username, username, name_len+1) == 0){
			tmp_user->face_id = 0;
			tmp_user->face_id_expired_round = 0;
			if(tmp_user->face_data){
				TEE_Free(tmp_user->face_data);
			}
			tmp_user->face_data = NULL;
			return 0;
		}
		tmp_user = tmp_user->next;
	}
	return 1;
}

uint32_t d3_core_check_user_passwd(user_info_t *entry, const char *username, const char *password)
{
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || username == NULL || password == NULL)
		return 1;
	uint32_t name_len = strlen(username);
	uint32_t pass_len = strlen(password);
	// bad username or password
	if (name_len > MAX_USERNAME_LEN || pass_len != PASSWORD_HASH_SIZE)
		return 1;
		
	tmp_user = entry;
	while (tmp_user != NULL){
		if (TEE_MemCompare(tmp_user->username, username, name_len+1) == 0 && tmp_user->magic == USER_MAGIC_NORMAL){
			if (TEE_MemCompare(tmp_user->password, password, pass_len+1) == 0){
				return 0;
			}
		}
		tmp_user = tmp_user->next;
	}
	return 1;
}

uint32_t d3_core_check_user_action_perm(user_info_t *user, user_info_t *op_user, uint32_t action)
{
	if (user == NULL || op_user == NULL)
		return 1;
	if(action > ACTION_COUNT || user->type > USER_TYPE_COUNT || op_user->type > USER_TYPE_COUNT){
		EMSG("d3_core_check_user_action_perm: action or user type is invalid!");
	}
	uint8_t perm_byte = GET_PERMISION_TABLE(user->type)[op_user->type][action];
	return perm_byte == 1? 0: 1;
}

uint32_t d3_core_check_user_face(user_info_t *entry, const char *username, const double *face_data, vec_float *similarity)
{
	user_info_t *tmp_user;
	vec_float tmp_similarity = 0.0;
	// check if entry is NULL
	if (entry == NULL || username == NULL || face_data == NULL)
		return 1;
	uint32_t name_len = strlen(username);
	// bad username or password
	if (name_len > MAX_USERNAME_LEN)
		return 1;
	tmp_user = entry;
	while (tmp_user != NULL){
		if (TEE_MemCompare(tmp_user->username, username, name_len+1) == 0 && tmp_user->magic == USER_MAGIC_NORMAL){
			if (!tmp_user-> face_id){
				//DMSG("D3TrustedCore: User %s face auth failed, face id not enabled!", username);
				return 2;
			}
			if (tmp_user->face_data != NULL){
				if (tmp_user->face_id_expired_round > 0){
					tmp_user->face_id_expired_round--;
				} else{
					d3_core_disable_user_face_id(tmp_user, username);
					EMSG("User [%s] face id auth failed! (face id expired)", username);
					return 3;
				}
				tmp_similarity = d3_core_euclidean_distance(tmp_user->face_data, face_data, FACE_DATA_SIZE);
				if (similarity != NULL){
					*similarity = tmp_similarity;
				}
				if (tmp_similarity >= FACE_SIMILARITY_THRESHOLD){
					IMSG("User [%s] face id auth success!", username);
					return 0;
				} else{
					EMSG("User [%s] face id auth failed (similarity < FACE_SIMILARITY_THRESHOL)!", username);
					return 1;
				}
			} else{
				EMSG("User [%s] face id auth failed! (face id disabled)", username);
				return 1;
			}
		}
		tmp_user = tmp_user->next;
	}
	return 1;
}

user_info_t *d3_core_get_user_by_name(user_info_t *entry, const char *username)
{
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL || username == NULL)
		return NULL;
	uint32_t name_len = strlen(username);
	// check if username and password are too long
	if (name_len > MAX_USERNAME_LEN)
		return NULL;
	tmp_user = entry;
	while (tmp_user != NULL){
		//IMSG("d3_core_get_user_by_name: Cmp %s", tmp_user->username);
		if (TEE_MemCompare(tmp_user->username, username, name_len+1) == 0){
			return tmp_user;
		}
		tmp_user = tmp_user->next;
	}
	return NULL;
}

user_info_t *d3_core_get_user_by_uid(user_info_t *entry, uint32_t uid)
{
	user_info_t *tmp_user;
	// check if entry is NULL
	if (entry == NULL)
		return NULL;
	tmp_user = entry;
	while (tmp_user != NULL){
		if (tmp_user->uid == uid){
			return tmp_user;
		}
		tmp_user = tmp_user->next;
	}
	return NULL;
}

user_info_t *d3_core_move_user_by_name(user_info_t **entry_from, user_info_t **entry_to, const char *username){
	if(entry_from == NULL || entry_to == NULL || username == NULL)
		return NULL;
	user_info_t *target_user = d3_core_get_user_by_name(*entry_from, username);
	if (target_user == NULL){
		//EMSG("d3_core_move_user: user %s not found", username);
		return NULL;
	}
	// move user from single chain entry_from to entry_to (chained by next region)
	if (target_user == *entry_from){
		// move first user
		*entry_from = target_user->next;
		target_user->next = NULL;
	} else{
		// move other user
		user_info_t *tmp_user = *entry_from;
		while (tmp_user->next != target_user){
			tmp_user = tmp_user->next;
		}
		tmp_user->next = target_user->next;
		target_user->next = NULL;
	}
	// add user to entry_to
	target_user->next = *entry_to;
	*entry_to = target_user;
	return target_user;
}



uint32_t d3_core_add_new_session(session_t **entry, user_info_t *user, const char *session_id){
	session_t *tmp_session = NULL;
	session_t *last_session = NULL;
	// check if entry is NULL
	if (entry == NULL)
		return 1;
	// check is user is NULL
	if (user == NULL || session_id == NULL)
		return 1;
	// check session_size
	uint32_t session_size = strlen(session_id);
	if (session_size > MAX_SESSION_LEN){
		//EMSG("d3_core_add_new_session: Can not add session, session_id is too long!");
		return 1;
	}
	if (*entry == NULL){
		// create first session
		tmp_session = TEE_Malloc(sizeof(session_t), TEE_MALLOC_FILL_ZERO);
		if (tmp_session == NULL)
			return 1;
		memset(tmp_session, 0, sizeof(session_t));
		// CHALL: Maybe we can create a UAF bug here by referencing the user pointer?
		tmp_session->uid = user->uid;
		//tmp_session->type = user->type;
		tmp_session->user_info = user;
		TEE_MemMove(tmp_session->session_id, session_id, session_size);
		tmp_session->next = NULL;
		*entry = tmp_session;
		return 0;
	} else{
		// move to the end of the list
		tmp_session = *entry;
		while (tmp_session){ // not null
			last_session = tmp_session;
			// find dup session
			if (tmp_session->uid == user->uid){
				// update old session id here
				tmp_session->user_info = user;
				memset(tmp_session->session_id, 0, sizeof(tmp_session->session_id));
				TEE_MemMove(tmp_session->session_id, session_id, session_size);
				return 0;
			}
			tmp_session = tmp_session->next;
		}		
		// create new session
		last_session->next = TEE_Malloc(sizeof(session_t), TEE_MALLOC_FILL_ZERO);
		if (last_session->next == NULL)
			return 1;
		memset(last_session->next, 0, sizeof(session_t));
		last_session->next->uid = user->uid;
		//last_session->next->type = user->type;
		last_session->next->user_info = user;
		TEE_MemMove(last_session->next->session_id, session_id, session_size);
		last_session->next->next = NULL;
		return 0;
	}
}

uint32_t d3_core_delete_session(session_t **entry, const char *session_id){
	if (entry == NULL || session_id == NULL){
		//EMSG("d3_core_delete_session: Can not get session, entry or session_id is NULL!");
		return 1;
	}
	// check session_size
	uint32_t session_size = strlen(session_id);
	if (session_size > MAX_SESSION_LEN){
		//EMSG("d3_core_delete_session: Can not get session, session_id is too long!");
		return 1;
	}
	session_t *tmp_session = *entry;
	session_t *last_session = NULL;
	while (tmp_session){
		if (TEE_MemCompare(tmp_session->session_id, session_id, session_size+1) == 0){
			// found session
			if (last_session == NULL){
				// first session
				*entry = tmp_session->next;
				TEE_Free(tmp_session);
				return 0;
			} else{
				// not first session
				last_session->next = tmp_session->next;
				TEE_Free(tmp_session);
				return 0;
			}
		}
		last_session = tmp_session;
		tmp_session = tmp_session->next;
	}
	return 1;
}

uint32_t d3_core_kickout_user(session_t **entry, user_info_t *user){
	if (entry == NULL || user == NULL){
		//EMSG("d3_core_delete_session: Can not get session, entry or user is NULL!");
		return 1;
	}
	if (user->magic != USER_MAGIC_NORMAL){
		EMSG("User magic error (!= USER_MAGIC_NORMAL)!");
		return 1;
	}
	// remove add node that satisfy: user->uid == tmp_session->user_info->uid
	session_t *tmp_session = *entry;
	session_t *last_session = NULL;
	while (tmp_session){
		if (tmp_session->uid == user->uid){
			// found session
			if (last_session == NULL){
				// first session
				*entry = tmp_session->next;
				TEE_Free(tmp_session);
				tmp_session = *entry;
			} else{
				// not first session
				last_session->next = tmp_session->next;
				TEE_Free(tmp_session);
				tmp_session = last_session->next;
			}
		} else{
			last_session = tmp_session;
			tmp_session = tmp_session->next;
		}
	}
	return 0;
}

uint32_t d3_core_gen_random_obj_id(char *buf, uint32_t buf_size){
	char tmp_buf[TEE_SHA256_HASH_SIZE];
	if (tmp_buf == NULL){
		//EMSG("d3_core_gen_random_obj_id: Can not get session, tmp_buf is NULL!");
		return 1;
	}
	TEE_GenerateRandom(tmp_buf, TEE_SHA256_HASH_SIZE);
	buf_size = buf_size == 0 ? OBJ_ID_SIZE : buf_size;
	d3_core_hexlify(tmp_buf, TEE_SHA256_HASH_SIZE, buf, buf_size);
	return 0;
}

uint32_t d3_core_create_secure_file(const char *filename, uint32_t parent_id, uint32_t owner, const uint8_t *data, uint32_t data_sz, uint32_t *ext_id_out){
	char obj_id[OBJ_ID_SIZE+1] = {0};
	file_node_t file_node = {0};
	uint32_t ext_id = ~0;
	TEE_ObjectHandle object;
	uint32_t obj_data_flag;
	TEE_Result res;

	if(!filename || !data){
		//EMSG("d3_core_create_secure_file: Can not create secure file, filename or data is NULL!");
		return 1;
	}
	if(strlen(filename) > MAX_FILE_NAME){
		EMSG("Can't create secure file! (strlen(filename) > MAX_FILE_NAME)");
		return 1;
	}
	if(data_sz > MAX_FILE_DATA){
		EMSG("Can't create secure file! (data_sz > MAX_FILE_DATA)");
		return 1;
	}

	// check parent id
	if(parent_id >= MAX_FILE_COUNT){
		EMSG("Can not create secure file! (parent_id >= MAX_FILE_COUNT)");
		return 1;
	} else{
		if(secure_fs[parent_id].node_type != FILE_NODE_DIR){
			//EMSG("d3_core_create_secure_file: Can not create secure file, parent id is not a directory!");
			return 1;
		}
		sec_file_t tmp_file;
		uint32_t tmp_rn = 0;
		for(int i = 0; i < MAX_FILE_COUNT; i++){
			if((secure_fs[i].node_type == FILE_NODE_FILE || secure_fs[i].node_type == FILE_NODE_DIR) && secure_fs[i].parent_id == parent_id){
				memset(&tmp_file, 0, sizeof(sec_file_t));
				// read file name by obj id
				TEE_ObjectHandle tmp_object;
				TEE_Result tmp_res;
				tmp_res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secure_fs[i].obj_id, OBJ_ID_SIZE, TEE_DATA_FLAG_ACCESS_READ, &tmp_object);
				if(tmp_res != TEE_SUCCESS){
					//EMSG("d3_core_create_secure_file: Can not create secure file, open file object failed!");
					continue;
				}
				tmp_res = TEE_ReadObjectData(tmp_object, &tmp_file, sizeof(sec_file_t), &tmp_rn);
				if(tmp_res != TEE_SUCCESS || tmp_rn != sizeof(sec_file_t)){
					//EMSG("d3_core_create_secure_file: Fail to read secfs file's (ext_id = %d) meta data.", i);
					TEE_CloseObject(tmp_object);
					continue;
				}
				uint32_t cmp_len = strlen(filename);
				// check if file name already exists
				if(tmp_file.magic == SEC_FILE_MAGIC && cmp_len == strlen(tmp_file.filename) && TEE_MemCompare(tmp_file.filename, filename, cmp_len) == 0){
					TEE_CloseObject(tmp_object);
					//EMSG("d3_core_create_secure_file: Can't create secure file, file name already exists!");
					return 2;
				}
				TEE_CloseObject(tmp_object);
			}
		}
	}

	// find an empty slot
	uint32_t last_del_id = ~0;
	for (int i = 0; i < MAX_FILE_COUNT; i++){
		if(secure_fs[i].node_type == FILE_NODE_EMPTY){
			ext_id = i;
			break;
		}
		if(secure_fs[i].node_type == FILE_NODE_DEL){
			last_del_id = i;
		}
	}
	if(ext_id == ~0){
		if(last_del_id != ~0){
			// reuse the slot that mark as deleted
			ext_id = last_del_id;
		} else{
			EMSG("No empty slots!");
			return 3;
		}
	}
	if(secure_fs[ext_id].node_type == FILE_NODE_DEL){
		// rewrtie the file node that marked as deleted
		uint32_t sec_file_sz = sizeof(sec_file_t) + data_sz;
		sec_file_t *new_file = TEE_Malloc(sec_file_sz, TEE_MALLOC_FILL_ZERO);
		if (new_file == NULL){
			//EMSG("d3_core_create_secure_file: Can not create secure file, TEE_Malloc failed!");
			return 1;
		}
		TEE_ObjectHandle old_object;
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&old_object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
			TEE_Free(new_file);
			return 1;
		}
		// read the old file
		uint32_t rn;
		res = TEE_ReadObjectData(old_object, new_file, sizeof(sec_file_t), &rn);
		if (res != TEE_SUCCESS || rn != sizeof(sec_file_t)) {
			//EMSG("TEE_ReadObjectData failed 0x%08x", res);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			TEE_Free(new_file);
			return 1;
		}
		// rewrite the file meta data
		memset(new_file->hash, 0, TEE_SHA256_HASH_SIZE);
		if(d3_core_sha256(data, data_sz, new_file->hash) != TEE_SHA256_HASH_SIZE){
			//EMSG("d3_core_create_secure_file: Can't create secure file, calc sha256 failed!");
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			TEE_Free(new_file);
			return 1;
		}
		new_file->magic = SEC_FILE_MAGIC;
		memset(new_file->filename, 0, MAX_FILE_NAME);
		strncpy(new_file->filename, filename, MAX_FILE_NAME);
		TEE_MemMove(new_file->data, data, data_sz);
		new_file->data_size = data_sz;
		new_file->name_size = strlen(new_file->filename);
		// truncate the file
		TEE_TruncateObjectData(old_object, 0);
		// write to the object
		res = TEE_SeekObjectData(old_object, 0, TEE_DATA_SEEK_SET);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_SeekObjectData failed 0x%08x", res);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			TEE_Free(new_file);
			return 1;
		}
		res = TEE_WriteObjectData(old_object, new_file, sec_file_sz);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_WriteObjectData failed 0x%08x", res);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			TEE_Free(new_file);
			return 1;
		}
		TEE_CloseObject(old_object);
		TEE_Free(new_file);
		MAKE_FILE_NODE_FILE(secure_fs[ext_id], parent_id, ext_id, owner, sec_file_sz, secure_fs[ext_id].obj_id);
	} else{
		// create new secure file
		uint32_t sec_file_sz = sizeof(sec_file_t) + data_sz;
		sec_file_t *sec_file = TEE_Malloc(sec_file_sz, TEE_MALLOC_FILL_ZERO);
		if (sec_file == NULL){
			//EMSG("d3_core_create_secure_file: Can not create secure file, TEE_Malloc failed!");
			return 1;
		}
		int ret = MAKE_SEC_FILE_REF(sec_file, filename, data, data_sz);	
		if(ret != 0){
			EMSG("d3_core_create_secure_file: MAKE_SEC_FILE_REF failed!");
			TEE_Free(sec_file);
			return 1;
		}

		// create an object, store the secure file into it
		d3_core_gen_random_obj_id(obj_id, 0);
		//IMSG("d3_core_create_secure_file: new obj_id = %s", obj_id);

		obj_data_flag = TEE_DATA_FLAG_ACCESS_READ |		/* we can later read the oject */
				TEE_DATA_FLAG_ACCESS_WRITE |			/* we can later write into the object */
				TEE_DATA_FLAG_ACCESS_WRITE_META |		/* we can later destroy or rename the object */
				TEE_DATA_FLAG_OVERWRITE;				/* destroy existing object of same ID */
		
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						obj_id, OBJ_ID_SIZE,
						obj_data_flag,
						TEE_HANDLE_NULL,
						NULL, 0,		/* we may not fill it right now */
						&object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
			TEE_Free(sec_file);
			return 1;
		}
		res = TEE_WriteObjectData(object, sec_file, sec_file_sz);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_WriteObjectData failed 0x%08x", res);
			TEE_CloseAndDeletePersistentObject1(object);
			TEE_Free(sec_file);
			return 1;
		} else {
			TEE_Free(sec_file);
			TEE_CloseObject(object);
		}

		// create file node to manage this object and hide raw obj_ids (only disclose ext_id to user)
		MAKE_FILE_NODE_FILE(secure_fs[ext_id], parent_id, ext_id, owner, sec_file_sz, obj_id);

		IMSG("d3_core_create_secure_file: New file created: ext_id = %d, filename = %s", ext_id, filename);
	}
	if(ext_id_out){
		*ext_id_out = ext_id;
	}
	return 0;
}

uint32_t d3_core_update_secure_file(uint32_t ext_id, uint8_t *data, uint32_t data_sz){
	if(ext_id >= MAX_FILE_COUNT){
		return 1;
	}
	if(!data || data_sz > MAX_FILE_DATA){
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_FILE){
		return 1;
	}
	TEE_ObjectHandle object;
	TEE_Result res;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&object);
	if (res != TEE_SUCCESS) {
		return 1;
	}
	sec_file_t file_meta;
	memset(&file_meta, 0, sizeof(sec_file_t));
	uint32_t read_sz = sizeof(sec_file_t);
	res = TEE_ReadObjectData(object, &file_meta, read_sz, &read_sz);
	if (res != TEE_SUCCESS || read_sz != sizeof(sec_file_t)) {
		TEE_CloseObject(object);
		return 1;
	}
	// check magic
	if(file_meta.magic != SEC_FILE_MAGIC){
		EMSG("Invalid magic!");
		TEE_CloseObject(object);
		return 1;
	}
	// update hash value
	if(d3_core_sha256(data, data_sz, file_meta.hash) != TEE_SHA256_HASH_SIZE){
		TEE_CloseObject(object);
		return 1;
	}
	// update file size
	file_meta.data_size = data_sz;
	// construct new file
	uint32_t new_file_sz = sizeof(sec_file_t) + data_sz;
	sec_file_t *new_file = TEE_Malloc(new_file_sz, TEE_MALLOC_FILL_ZERO);
	if (new_file == NULL){
		TEE_CloseObject(object);
		return 1;
	}
	TEE_MemMove(new_file, &file_meta, sizeof(sec_file_t));
	TEE_MemMove(new_file->data, data, data_sz);
	// truncate file
	TEE_TruncateObjectData(object, 0);
	// update file into object
	if (TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET) != TEE_SUCCESS) {
		TEE_CloseObject(object);
		return 1;
	}
	if (TEE_WriteObjectData(object, new_file, new_file_sz) != TEE_SUCCESS) {
		TEE_CloseObject(object);
		return 1;
	}
	// update file size in file node
	secure_fs[ext_id].file_size = new_file_sz;
	// success
	TEE_CloseObject(object);
	return 0;
}

uint32_t d3_core_create_secure_dir(const char *dir_name, uint32_t parent_id, uint32_t owner, uint32_t *ext_id_out){
	if(!dir_name){
		//EMSG("d3_core_create_secure_dir: Can not create secure dir, dir_name is NULL!");
		return 1;
	}
	if(strlen(dir_name) > MAX_DIR_NAME){
		//EMSG("d3_core_create_secure_dir: Can not create secure dir, dir_name is too long!");
		return 1;
	}
	if(parent_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_create_secure_dir: Can not create secure dir, parent_id is too large!");
		return 1;
	}
	if(secure_fs[parent_id].node_type != FILE_NODE_DIR){
		EMSG("Can not create secure dir! (node_type != FILE_NODE_DIR)");
		return 1;
	}
	// check if the dir_name is already used
	sec_file_t tmp_file;
	for(int i = 0; i < MAX_FILE_COUNT; i++){
		// maybe we can set a cmp buf here?
		if((secure_fs[i].node_type == FILE_NODE_DIR || secure_fs[i].node_type == FILE_NODE_FILE) && secure_fs[i].parent_id == parent_id){
			memset(&tmp_file, 0, sizeof(sec_file_t));
			// read file name by obj id
			TEE_ObjectHandle tmp_object;
			TEE_Result tmp_res;
			tmp_res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE, secure_fs[i].obj_id, OBJ_ID_SIZE, TEE_DATA_FLAG_ACCESS_READ, &tmp_object);
			if(tmp_res != TEE_SUCCESS){
				//EMSG("d3_core_create_secure_dir: Can not create secure dir, open file object failed!");
				continue;
			}
			uint32_t tmp_rn;
			tmp_res = TEE_ReadObjectData(tmp_object, &tmp_file, sizeof(sec_file_t), &tmp_rn);
			if(tmp_res != TEE_SUCCESS || tmp_rn != sizeof(sec_file_t)){
				//EMSG("d3_core_create_secure_dir: Fail to read secfs file (ext_id = %d) meta data.", i);
				TEE_CloseObject(tmp_object);
				continue;
			}
			uint32_t cmp_len = strlen(dir_name);
			if(tmp_file.magic == SEC_FILE_MAGIC && cmp_len == strlen(tmp_file.filename) && TEE_MemCompare(tmp_file.filename, dir_name, cmp_len) == 0){
				TEE_CloseObject(tmp_object);
				//EMSG("d3_core_create_secure_dir: Can not create secure dir, dir name already exists!");
				return 2;
			}
			TEE_CloseObject(tmp_object);
		} else{
			continue;
		}
	}
	// find an empty slot
	uint32_t last_del_id = ~0;
	uint32_t ext_id = ~0;
	for (int i = 0; i < MAX_FILE_COUNT; i++){
		if(secure_fs[i].node_type == FILE_NODE_EMPTY){
			ext_id = i;
			break;
		}
		if(secure_fs[i].node_type == FILE_NODE_DEL){
			last_del_id = i;
		}
	}
	if(ext_id == ~0){
		if(last_del_id != ~0){
			// reuse the slot that mark as deleted
			ext_id = last_del_id;
		} else{
			EMSG("No empty slots!");
			return 3;
		}
	}
	// rewrtie the file node
	if(secure_fs[ext_id].node_type == FILE_NODE_DEL){
		// if node is marked as FILE_NODE_DEL, update dir info in the same node's obj_id
		sec_file_t *new_file = TEE_Malloc(sizeof(sec_file_t), TEE_MALLOC_FILL_ZERO);
		if(!new_file){
			//EMSG("d3_core_create_secure_dir: Can not create secure dir, malloc failed!");
			return 1;
		}
		TEE_Result res;
		TEE_ObjectHandle old_object;
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&old_object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
			TEE_Free(new_file);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			return 1;
		}
		// read old file
		uint32_t rn;
		res = TEE_ReadObjectData(old_object, new_file, sizeof(sec_file_t), &rn);
		if (res != TEE_SUCCESS || rn != sizeof(sec_file_t)) {
			//EMSG("TEE_ReadObjectData failed 0x%08x", res);
			TEE_Free(new_file);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			return 1;
		}
		// update the file
		/* if(MAKE_SEC_DIR_REF(new_file, dir_name) != 0){
			EMSG("d3_core_create_secure_dir: Can not create secure dir, make dir ref failed!");
			TEE_Free(new_file);
			TEE_CloseObject(old_object);
			return 1;
		} */
		// reweite file meta data
		memset(new_file->hash, 0, TEE_SHA256_HASH_SIZE);
		new_file->magic = SEC_FILE_MAGIC;
		memset(new_file->filename, 0, MAX_FILE_NAME);
		strncpy(new_file->filename, dir_name, MAX_FILE_NAME);
		new_file->status = SEC_FILE_STATUS_DIR;
		new_file->name_size = strlen(new_file->filename);
		new_file->data_size = 0;
		// truncate the file
		TEE_TruncateObjectData(old_object, 0);
		// write into object
		res = TEE_SeekObjectData(old_object, 0, TEE_DATA_SEEK_SET);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_SeekObjectData failed 0x%08x", res);
			TEE_Free(new_file);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			return 1;
		}
		res = TEE_WriteObjectData(old_object, new_file, sizeof(sec_file_t));
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_WriteObjectData failed 0x%08x", res);
			TEE_Free(new_file);
			TEE_CloseAndDeletePersistentObject1(old_object);
			MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
			return 1;
		}
		TEE_Free(new_file);
		TEE_CloseObject(old_object);
		// update file node
		MAKE_FILE_NODE_DIR(secure_fs[ext_id], parent_id, ext_id, owner, secure_fs[ext_id].obj_id);
	} else{
		// is there is an empty node, create an new object to save dir info
		sec_file_t *sec_file = TEE_Malloc(sizeof(sec_file_t), TEE_MALLOC_FILL_ZERO);
		if(!sec_file){
			//EMSG("d3_core_create_secure_dir: Can not create secure dir, malloc failed!");
			return 1;
		}
		if(MAKE_SEC_DIR_REF(sec_file, dir_name) != 0){
			EMSG("d3_core_create_secure_dir: MAKE_SEC_DIR_REF failed!");
			TEE_Free(sec_file);
			return 1;
		}
		// gen a new obj_id
		char new_obj_id[OBJ_ID_SIZE+1] = {0};
		d3_core_gen_random_obj_id(new_obj_id, 0);
		// create a new object
		TEE_ObjectHandle object;
		TEE_Result res;
		res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						new_obj_id, OBJ_ID_SIZE,
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE |
						TEE_DATA_FLAG_ACCESS_WRITE_META |
						TEE_DATA_FLAG_OVERWRITE,
						TEE_HANDLE_NULL,
						NULL, 0,		/* we may not fill it right now */
						&object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_CreatePersistentObject failed 0x%08x", res);
			TEE_Free(sec_file);
			return 1;
		}
		// write into object
		res = TEE_WriteObjectData(object, sec_file, sizeof(sec_file_t));
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_WriteObjectData failed 0x%08x", res);
			TEE_CloseAndDeletePersistentObject1(object);
			TEE_Free(sec_file);
			return 1;
		}
		TEE_Free(sec_file);
		TEE_CloseObject(object);
		// update file node
		MAKE_FILE_NODE_DIR(secure_fs[ext_id], parent_id, ext_id, owner, new_obj_id);
	}
	if(ext_id_out){
		*ext_id_out = ext_id;
	}
	return 0;
}

uint32_t d3_core_delete_secure_file(uint32_t ext_id, uint32_t erase){
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_delete_secure_file: Can not delete secure file, ext_id is too large!");
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_FILE){
		EMSG("Can't delete secure file! (node_type != FILE_NODE_FILE)");
		return 1;
	}
	if(erase){
		// delete the object
		TEE_Result res;
		TEE_ObjectHandle object;
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&object);
		if (res != TEE_SUCCESS) {
			return 1;
		}
		res = TEE_CloseAndDeletePersistentObject1(object);
		if (res != TEE_SUCCESS) {
			return 1;
		}
		// delete the file node
		memset(&secure_fs[ext_id], 0, sizeof(file_node_t));
		secure_fs[ext_id].node_type = FILE_NODE_EMPTY;
	} else{
		// just mark it as deleted
		secure_fs[ext_id].node_type = FILE_NODE_DEL;
	}
	return 0;
}

uint32_t d3_core_delete_secure_dir(uint32_t ext_id, uint32_t recursive){
	if(ext_id >= MAX_FILE_COUNT){
		return 1;
	}
	if(ext_id == root_ext_id){
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_DIR){
		return 1;
	}
	if(recursive){
		// delete the object recursively (only mark it as deleted)
		for(uint32_t i=0; i<MAX_FILE_COUNT; i++){
			if(secure_fs[i].parent_id == ext_id){
				if(secure_fs[i].node_type == FILE_NODE_FILE){
					if(d3_core_delete_secure_file(i, 0) != 0){
						return 3;
					}
				} else if(secure_fs[i].node_type == FILE_NODE_DIR){
					// recursive
					if(d3_core_delete_secure_dir(i, 1) != 0){
						return 3;
					}
				}
			}
		}
		secure_fs[ext_id].node_type = FILE_NODE_DEL;
		return 0;
	} else{
		// no recursive
		for(uint32_t i=0; i<MAX_FILE_COUNT; i++){
			if(secure_fs[i].parent_id == ext_id){
				//EMSG("d3_core_delete_secure_dir: Can not delete secure dir, dir is not empty!");
				return 2;
			}
		}
		TEE_Result res;
		TEE_ObjectHandle object;
		res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
						TEE_DATA_FLAG_ACCESS_READ |
						TEE_DATA_FLAG_ACCESS_WRITE_META,
						&object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
			return 1;
		}
		res = TEE_CloseAndDeletePersistentObject1(object);
		if (res != TEE_SUCCESS) {
			//EMSG("TEE_CloseAndDeletePersistentObject1 failed 0x%08x", res);
			return 1;
		}
		// delete the file node
		MAKE_FILE_NODE_EMPTY(secure_fs[ext_id]);
		return 0;
	}
}

uint32_t d3_core_get_sec_file_info(uint32_t ext_id, file_info_t *file_info){
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_get_file_info: Can not get file info, ext_id is too large!");
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_FILE){
		//EMSG("d3_core_get_file_info: Can not get file info, ext_id is not a file!");
		return 1;
	}
	// TODO: CONSTRUCT FILE INFO
	uint32_t data_size = secure_fs[ext_id].file_size - sizeof(sec_file_t);
	file_info->magic = 0x656c6966; // "file"
	file_info->node_type = FILE_NODE_FILE;
	file_info->file_size = data_size; // size without sec_file_t header
	file_info->ext_id = ext_id;
	file_info->parent_id = secure_fs[ext_id].parent_id;
	file_info->owner = secure_fs[ext_id].owner;
	// get object from secure storage by obj_id
	TEE_Result res;
	TEE_ObjectHandle object;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&object);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
		return 1;
	}
	// read the object
	sec_file_t *sec_file = TEE_Malloc(secure_fs[ext_id].file_size, TEE_MALLOC_FILL_ZERO);
	if(sec_file == NULL){
		//EMSG("d3_core_get_sec_file_info: Can not get filename, TEE_Malloc failed!");
		return 1;
	}
	uint32_t read_sz = secure_fs[ext_id].file_size;
	res = TEE_ReadObjectData(object, sec_file, read_sz, &read_sz);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_ReadObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	// check magic
	if(sec_file->magic != SEC_FILE_MAGIC){ // "file"
		//EMSG("d3_core_get_sec_file_info: Can not get file info, magic check failed!");
		TEE_Free(sec_file);
		return 2;
	}
	// check hash
	char true_hash[TEE_SHA256_HASH_SIZE] = {0};
	d3_core_sha256(sec_file->data, data_size, true_hash);
	if(TEE_MemCompare(true_hash, sec_file->hash, TEE_SHA256_HASH_SIZE) != 0){
		//EMSG("d3_core_get_sec_file_info: Can not get file info, hash check failed!");
		TEE_Free(sec_file);
		return 2;
	}
	// copy hash
	d3_core_hexlify(sec_file->hash, TEE_SHA256_HASH_SIZE, file_info->hash, TEE_SHA256_HASH_SIZE*2);
	// copy filename
	//TEE_MemMove(file_info->filename, sec_file->filename, strlen(sec_file->filename)); // bug here
	TEE_MemMove(file_info->filename, sec_file->filename, sec_file->name_size); // bug here
	// close object
	TEE_CloseObject(object);
	TEE_Free(sec_file);
	return 0;
}

uint32_t d3_core_get_sec_dir_info(uint32_t ext_id, dir_info_t *dir_info){
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_get_sec_dir_info: Can not get dir info, ext_id is too large!");
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_DIR){
		//EMSG("d3_core_get_sec_dir_info: Can not get dir info, ext_id is not a dir!");
		return 1;
	}
	dir_info->magic = 0x726964; // "dir"
	dir_info->node_type = FILE_NODE_DIR;
	dir_info->ext_id = ext_id;
	dir_info->parent_id = secure_fs[ext_id].parent_id;
	dir_info->owner = secure_fs[ext_id].owner;
	// get object from secure storage by obj_id
	TEE_Result res;
	TEE_ObjectHandle object;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&object);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
		return 1;
	}	
	// read the object
	sec_dir_t *sec_file = TEE_Malloc(sizeof(sec_dir_t), TEE_MALLOC_FILL_ZERO);
	if(sec_file == NULL){
		//EMSG("d3_core_get_sec_dir_info: Can not get filename, TEE_Malloc failed!");
		return 1;
	}
	uint32_t read_sz = sizeof(sec_dir_t);
	res = TEE_ReadObjectData(object, sec_file, read_sz, &read_sz);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_ReadObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	// check magic
	if(sec_file->magic != SEC_FILE_MAGIC){
		//EMSG("d3_core_get_sec_dir_info: Can not get dir info, magic check failed!");
		TEE_Free(sec_file);
		return 2;
	}
	// copy filename
	// strncpy(dir_info->dir_name, sec_file->filename, MAX_FILE_NAME);
	// TEE_MemMove(dir_info->dir_name, sec_file->filename, strlen(sec_file->filename));  // bug 3
	TEE_MemMove(dir_info->dir_name, sec_file->filename, sec_file->name_size);  // bug 3
	// close object
	TEE_CloseObject(object);
	TEE_Free(sec_file);
	// set sub_items
	memset(dir_info->sub_items, 0, MAX_FILE_COUNT*sizeof(uint8_t));
	for(int i=0; i<MAX_FILE_COUNT; i++){
		if(secure_fs[i].parent_id == ext_id && (secure_fs[i].node_type == FILE_NODE_DIR || secure_fs[i].node_type == FILE_NODE_FILE)){
			dir_info->sub_items[i] = 1;
		}
	}
	return 0;
}

uint32_t d3_core_read_sec_file(uint32_t ext_id, char *file_data, uint32_t max_sz, uint32_t *data_sz){
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_get_file_info: Can not get file info, ext_id is too large!");
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_FILE){
		//EMSG("d3_core_get_file_info: Can not get file info, ext_id is not a file!");
		return 1;
	}
	TEE_Result res;
	TEE_ObjectHandle object;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&object);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
		return 1;
	}
	// read the object
	sec_file_t *sec_file = TEE_Malloc(secure_fs[ext_id].file_size, TEE_MALLOC_FILL_ZERO);
	if(sec_file == NULL){
		//EMSG("d3_core_get_sec_file_data: Can not get filename, TEE_Malloc failed!");
		return 1;
	}
	uint32_t read_sz = secure_fs[ext_id].file_size;
	res = TEE_ReadObjectData(object, sec_file, read_sz, &read_sz);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_ReadObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	char hash[TEE_SHA256_HASH_SIZE+1] = {0};
	d3_core_sha256(sec_file->data, secure_fs[ext_id].file_size - sizeof(sec_file_t), hash);
	if(TEE_MemCompare(hash, sec_file->hash, TEE_SHA256_HASH_SIZE) != 0){
		//EMSG("d3_core_get_sec_file_data: Hash of file data is not correct!");
		TEE_CloseObject(object);
		TEE_Free(sec_file);
		return 1;
	}
	// check magic
	if(sec_file->magic != SEC_FILE_MAGIC){
		//EMSG("d3_core_get_sec_file_data: Can not get file data, magic check failed!");
		TEE_CloseObject(object);
		TEE_Free(sec_file);
		return 2;
	}
	// copy filedata
	uint32_t out_sz = max_sz < secure_fs[ext_id].file_size - sizeof(sec_file_t) ? max_sz : secure_fs[ext_id].file_size - sizeof(sec_file_t);
	TEE_MemMove(file_data, sec_file->data, out_sz);
	*data_sz = out_sz;
	// close object
	TEE_CloseObject(object);
	TEE_Free(sec_file);
	return 0;
}

uint32_t d3_core_rename_sec_file(uint32_t ext_id, const char *new_name){
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("d3_core_rename_sec_file: Can not rename file, ext_id is too large!");
		return 1;
	}
	if(secure_fs[ext_id].node_type != FILE_NODE_FILE){
		//EMSG("d3_core_rename_sec_file: Can not rename file, ext_id is not a file!");
		return 1;
	}
	if(strlen(new_name) > MAX_FILE_NAME){
		//EMSG("d3_core_rename_sec_file: Can not rename file, new_name is too long!");
		return 1;
	}
	TEE_Result res;
	TEE_ObjectHandle object;
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
					secure_fs[ext_id].obj_id, OBJ_ID_SIZE,
					TEE_DATA_FLAG_ACCESS_READ |
					TEE_DATA_FLAG_ACCESS_WRITE |
					TEE_DATA_FLAG_ACCESS_WRITE_META,
					&object);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_OpenPersistentObject failed 0x%08x", res);
		return 1;
	}
	// read the object
	sec_file_t *sec_file = TEE_Malloc(secure_fs[ext_id].file_size, TEE_MALLOC_FILL_ZERO);
	if(sec_file == NULL){
		//EMSG("d3_core_get_sec_file_data: Can not get filename, TEE_Malloc failed!");
		return 1;
	}
	uint32_t read_sz = secure_fs[ext_id].file_size;
	res = TEE_ReadObjectData(object, sec_file, read_sz, &read_sz);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_ReadObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	//IMSG("replace filename %s with %s", sec_file->filename, new_name);
	memset(sec_file->filename, 0, MAX_FILE_NAME);
	TEE_MemMove(sec_file->filename, new_name, strlen(new_name));
	sec_file->name_size = strlen(sec_file->filename);
	// write the object
	res = TEE_SeekObjectData(object, 0, TEE_DATA_SEEK_SET);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_SeekObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	res = TEE_WriteObjectData(object, sec_file, secure_fs[ext_id].file_size);
	if (res != TEE_SUCCESS) {
		//EMSG("TEE_WriteObjectData failed 0x%08x", res);
		TEE_Free(sec_file);
		return 1;
	}
	// close object
	TEE_CloseObject(object);
	TEE_Free(sec_file);
	return 0;
}

uint32_t d3_core_get_secfs_slots_info(uint8_t *slot_info, uint32_t count){
	if(slot_info == NULL || count > MAX_FILE_COUNT || count == 0){
		return 1;
	}
	for(uint32_t i = 0; i < count; i++){
		if(secure_fs[i].node_type == FILE_NODE_FILE
		|| secure_fs[i].node_type == FILE_NODE_DIR){
			slot_info[i] = secure_fs[i].node_type;
		} else{
			slot_info[i] = FILE_NODE_EMPTY;
		}
	}
	return 0;
}

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("D3TrustedCore: TA_CreateEntryPoint");
	// init user permissions
	int i = 0;
	memset(GET_PERMISION_TABLE(USER_TYPE_ADMIN), 0, USER_TYPE_COUNT*ACTION_COUNT*sizeof(uint8_t));
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_PASSWD] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_CREATE_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_DELETE_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_READ_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_WRITE_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_LIST_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_CREATE_DIR] = 1;
	GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_ADMIN][ACTION_PERMISSON_DELETE_DIR] = 1;
	for(i = 0; i < ACTION_COUNT; i++){
		GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_USER][i] = 1;
		GET_PERMISION_TABLE(USER_TYPE_ADMIN)[USER_TYPE_GUEST][i] = 1;
	}
	memset(GET_PERMISION_TABLE(USER_TYPE_USER), 0, USER_TYPE_COUNT*ACTION_COUNT*sizeof(uint8_t));
	GET_PERMISION_TABLE(USER_TYPE_USER)[USER_TYPE_USER][ACTION_PERMISSON_PASSWD] = 1;
	GET_PERMISION_TABLE(USER_TYPE_USER)[USER_TYPE_USER][ACTION_PERMISSON_READ_FILE] = 1;
	GET_PERMISION_TABLE(USER_TYPE_USER)[USER_TYPE_USER][ACTION_PERMISSON_LIST_FILE] = 1;
	for(i = 0; i < ACTION_COUNT; i++){
		GET_PERMISION_TABLE(USER_TYPE_USER)[USER_TYPE_GUEST][i] = 1;
	}
	memset(GET_PERMISION_TABLE(USER_TYPE_GUEST), 0, USER_TYPE_COUNT*ACTION_COUNT*sizeof(uint8_t));
	GET_PERMISION_TABLE(USER_TYPE_GUEST)[USER_TYPE_GUEST][ACTION_PERMISSON_PASSWD] = 1;

	// init users
	#define USER_PASS_HASH_ADMIN "e31675054db76809ca6a90373ed91da365e3e4f090b8eabef63aef8af1eedec0"
	if(d3_core_add_user_info(&user_info, USER_MAGIC_NORMAL, 0, USER_TYPE_ADMIN, "admin", USER_PASS_HASH_ADMIN))
		return TEE_ERROR_GENERIC;

	#define USER_PASS_HASH_EQQIE "bae17a02df5e3c59c13fcb1c38cac31f295bf5c68ba084482904076651c3b213"
	if(d3_core_add_user_info(&user_info, USER_MAGIC_NORMAL, 1000, USER_TYPE_USER, "eqqie", USER_PASS_HASH_EQQIE))
		return TEE_ERROR_GENERIC;

	#define USER_PASS_HASH_GUEST "b6e47f52784b98385539c5774c172d6c4f44d7e41af5fa680fac889c0b62ab41"
	if(d3_core_add_user_info(&user_info, USER_MAGIC_NORMAL, 65534, USER_TYPE_GUEST, "guest", USER_PASS_HASH_GUEST))
		return TEE_ERROR_GENERIC;
	d3_core_disable_user_face_id(user_info, "admin");
	d3_core_enable_user_face_id(user_info, "eqqie", face_data_eqqie, 1);
	d3_core_disable_user_face_id(user_info, "guest");

	// init secure FS
	for (i = 0; i < MAX_FILE_COUNT; i++) {
		MAKE_FILE_NODE_EMPTY(secure_fs[i]);
	}
	// gen a random obj_id
	char obj_id[OBJ_ID_SIZE+1] = {0};
	TEE_GenerateRandom(obj_id, OBJ_ID_SIZE);
	TEE_ObjectHandle root_obj;
	TEE_Result res;
	res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
							obj_id, OBJ_ID_SIZE,
							TEE_DATA_FLAG_ACCESS_READ |
							TEE_DATA_FLAG_ACCESS_WRITE |
							TEE_DATA_FLAG_ACCESS_WRITE_META |
							TEE_DATA_FLAG_OVERWRITE,
							TEE_HANDLE_NULL,
							NULL, 0,		/* we may not fill it right now */
							&root_obj);
	if (res != TEE_SUCCESS) {
		return TEE_ERROR_GENERIC;
	}
	// create a new sec_file_t
	sec_file_t *sec_file = TEE_Malloc(sizeof(sec_file_t), TEE_MALLOC_FILL_ZERO);
	if (sec_file == NULL) {
		return TEE_ERROR_GENERIC;
	}
	if(MAKE_SEC_DIR_REF(sec_file, "secfs-root")){
		return TEE_ERROR_GENERIC;
	}
	// write the sec_file_t to the object
	TEE_WriteObjectData(root_obj, sec_file, sizeof(sec_file_t));
	TEE_CloseObject(root_obj);
	TEE_Free(sec_file);
	// update the root node
	MAKE_FILE_NODE_DIR(secure_fs[root_ext_id], ~0, 0, 0, obj_id);


	DMSG("D3TrustedCore: Created!");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("D3TrustedCore: Destroyed!");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	/* check client and handle session resource release, if any */
	DMSG("D3TrustedCore: Session has been opened!");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Unused parameters */
	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx; /* Unused parameter */
	//IMSG("D3CTF TA session has been closed!");
}

// *************************************************************************

static TEE_Result test_debug_log(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;


	return TEE_SUCCESS;
}

static TEE_Result d3_auth_user_passwd(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (user_info == NULL)
		return TEE_ERROR_GENERIC;

	uint32_t valid_name_len = params[0].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[0].memref.size;
	uint32_t valid_passwd_len = params[1].memref.size > MAX_PASSWORD_LEN ? MAX_PASSWORD_LEN : params[1].memref.size;
	uint8_t *username = TEE_Malloc(valid_name_len+8, TEE_MALLOC_FILL_ZERO);
	uint8_t *password = TEE_Malloc(valid_passwd_len+8, TEE_MALLOC_FILL_ZERO);

	if(username == NULL || password == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	// ensure string truncation
	strncpy(username, (char *)params[0].memref.buffer, valid_name_len+1);
	strncpy(password, (char *)params[1].memref.buffer, valid_passwd_len+1);
	IMSG("D3TrustedCore: Auth user: %s\n", username);

	uint8_t *pass_hash_hex = TEE_Malloc(TEE_SHA256_HASH_SIZE*2+1, TEE_MALLOC_FILL_ZERO);
	if (pass_hash_hex == NULL){
		TEE_Free(username);
		TEE_Free(password);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	if(d3_core_sha256_and_hexlify(password, strlen(password), pass_hash_hex, TEE_SHA256_HASH_SIZE*2)!=0){
		TEE_Free(pass_hash_hex);
		return TEE_ERROR_GENERIC;
	}
	
	bool check_result = d3_core_check_user_passwd(user_info, username, pass_hash_hex)? false:true;

	if(check_result){
		user_info_t *user = d3_core_get_user_by_name(user_info, username);
		TEE_Free(username);
		TEE_Free(password);
		TEE_Free(pass_hash_hex);

		if(user->magic != USER_MAGIC_NORMAL){
			EMSG("D3TrustedCore: User magic error! (!= USER_MAGIC_NORMAL)");
			return TEE_ERROR_GENERIC;
		}

		uint8_t *session_id = TEE_Malloc(TEE_SHA256_HASH_SIZE+8, TEE_MALLOC_FILL_ZERO);
		if(session_id == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;

		TEE_GenerateRandom(session_id, TEE_SHA256_HASH_SIZE);

		// hex encode
		uint8_t *session_id_hex = TEE_Malloc(HTTP_SESSION_LEN+8, TEE_MALLOC_FILL_ZERO);
		if(session_id_hex == NULL)
			return TEE_ERROR_OUT_OF_MEMORY;
		d3_core_hexlify(session_id, TEE_SHA256_HASH_SIZE, session_id_hex, HTTP_SESSION_LEN);
		TEE_Free(session_id);

		// copy to output buffer
		if (params[2].memref.size < HTTP_SESSION_LEN){
			TEE_Free(session_id_hex);
			return TEE_ERROR_SHORT_BUFFER;
		}
		TEE_MemMove(params[2].memref.buffer, session_id_hex, HTTP_SESSION_LEN);
		params[2].memref.size = HTTP_SESSION_LEN;

		// add new session
		if(d3_core_add_new_session(&session, user, session_id_hex)){
			TEE_Free(session_id_hex);
			return TEE_ERROR_GENERIC;
		} else{
			IMSG("D3TrustedCore: Add new session!");
			TEE_Free(session_id_hex);
			return TEE_SUCCESS;
		}		
	} else{
		TEE_Free(username);
		TEE_Free(password);
		TEE_Free(pass_hash_hex);
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result d3_auth_session_id(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > TEE_SHA256_HASH_SIZE*2 ? TEE_SHA256_HASH_SIZE*2 : params[0].memref.size;
	uint8_t session_id[TEE_SHA256_HASH_SIZE*2+8];
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	IMSG("D3TrustedCore: Auth session: %s\n", session_id);

	// check session id
	uint32_t res = d3_core_check_valid_session(session, session_id, NULL);
	if(res == 0){
		return TEE_SUCCESS;
	} else if(res == 3){
		EMSG("D3TrustedCore: Session expired!");
		return TEE_ERROR_NOT_SUPPORTED;
	}
	else{
		EMSG("D3TrustedCore: Session not found!");
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result d3_get_user_info(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > TEE_SHA256_HASH_SIZE*2 ? TEE_SHA256_HASH_SIZE*2 : params[0].memref.size;
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *target_session = NULL;
	if(d3_core_check_valid_session(session, session_id, &target_session) != 0){
		EMSG("D3TrustedCore: Auth session_id failed, session not found!");
		TEE_Free(session_id);
		return TEE_ERROR_GENERIC;
	}

	user_info_t *user_info = target_session->user_info;
	user_info_out_t *user_info_out = TEE_Malloc(sizeof(user_info_out_t), TEE_MALLOC_FILL_ZERO);
	if(user_info_out == NULL){
		TEE_Free(session_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	MAKE_USER_INFO_OUT_REF(user_info, user_info_out);
	// copy to output buffer
	if (params[1].memref.size < sizeof(user_info_out_t)){
		TEE_Free(session_id);
		TEE_Free(user_info_out);
		return TEE_ERROR_SHORT_BUFFER;
	}
	TEE_MemMove(params[1].memref.buffer, user_info_out, sizeof(user_info_out_t));
	params[1].memref.size = sizeof(user_info_out_t);
	IMSG("D3TrustedCore: Read profile of %s.", user_info->username);
	TEE_Free(session_id);
	TEE_Free(user_info_out);
	return TEE_SUCCESS;
}

static TEE_Result d3_auth_user_face_id(uint32_t param_types,
	TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	if (user_info == NULL)
		return TEE_ERROR_GENERIC;

	// can't be NULL at the same time
	if (params[2].memref.buffer == NULL && params[3].memref.buffer == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (params[2].memref.buffer && params[2].memref.size < HTTP_SESSION_LEN){
		return TEE_ERROR_SHORT_BUFFER;
	}

	if (params[3].memref.buffer && params[3].memref.size < sizeof(vec_float)){
		return TEE_ERROR_SHORT_BUFFER;
	}

	// get valid username and password length
	uint32_t valid_name_len = params[0].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[0].memref.size;
	uint32_t face_data_len = params[1].memref.size;
	if(face_data_len != FACE_DATA_SIZE*sizeof(vec_float)){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	// read username and password
	uint8_t *username = TEE_Malloc(valid_name_len+8, TEE_MALLOC_FILL_ZERO);
	vec_float face_data[FACE_DATA_SIZE];
	memset(face_data, 0, FACE_DATA_SIZE*sizeof(vec_float));

	if(username == NULL || face_data == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	//TEE_MemMove(username, params[0].memref.buffer, valid_name_len);
	strncpy(username, params[0].memref.buffer, valid_name_len+1);
	TEE_MemMove((uint8_t *)face_data, params[1].memref.buffer, face_data_len);
	IMSG("D3TrustedCore: Auth user: %s (Face ID)\n", username);

	// TODO: check username and face data
	// check username and face data
	vec_float similarity = 0.0;
	uint32_t check_result = d3_core_check_user_face(user_info, username, face_data, &similarity);
	// write similarity
	if (params[3].memref.buffer){
		TEE_MemMove(params[3].memref.buffer, &similarity, sizeof(vec_float));
		params[3].memref.size = sizeof(vec_float);
	}

	DMSG("after d3_core_check_user_face()");

	if (check_result == 0){
		// success
		user_info_t *user = d3_core_get_user_by_name(user_info, username);
		TEE_Free(username);
		//TEE_Free(face_data);

		if(user->magic != USER_MAGIC_NORMAL){
			EMSG("User magic error! (!= USER_MAGIC_NORMAL)");
			return TEE_ERROR_GENERIC;
		}
	
		if(params[2].memref.buffer){
			uint8_t *session_id = TEE_Malloc(TEE_SHA256_HASH_SIZE+8, TEE_MALLOC_FILL_ZERO);
			if(session_id == NULL)
				return TEE_ERROR_OUT_OF_MEMORY;

			TEE_GenerateRandom(session_id, TEE_SHA256_HASH_SIZE);

			uint8_t *session_id_hex = TEE_Malloc(HTTP_SESSION_LEN+8, TEE_MALLOC_FILL_ZERO);
			if(session_id_hex == NULL)
				return TEE_ERROR_OUT_OF_MEMORY;
			d3_core_hexlify(session_id, TEE_SHA256_HASH_SIZE, session_id_hex, HTTP_SESSION_LEN);
			TEE_Free(session_id);

			TEE_MemMove(params[2].memref.buffer, session_id_hex, HTTP_SESSION_LEN);
			params[2].memref.size = HTTP_SESSION_LEN;

			// add new session
			if(d3_core_add_new_session(&session, user, session_id_hex)){
				TEE_Free(session_id_hex);
				return TEE_ERROR_GENERIC;
			} else{
				IMSG("D3TrustedCore: Add new session!", session_id_hex);
				TEE_Free(session_id_hex);
				return TEE_SUCCESS;
			}
		} else{
			return TEE_SUCCESS;
		}
	}
	if (check_result == 2){
		TEE_Free(username);
		return TEE_ERROR_NOT_SUPPORTED;
	} 
	if (check_result == 3){
		TEE_Free(username);
		return TEE_ERROR_SECURITY;
	}
	TEE_Free(username);
	return TEE_ERROR_GENERIC;
}

static TEE_Result d3_user_logout(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(session_id, params[0].memref.buffer, valid_session_id_len);
	// check session id
	if(d3_core_check_valid_session(session, session_id, NULL) != 0){
		TEE_Free(session_id);
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_delete_session(&session, session_id)){
		TEE_Free(session_id); 
		return TEE_ERROR_GENERIC;
	} else{
		IMSG("D3TrustedCore: Delete session: %s\n", session_id);
		TEE_Free(session_id);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_user_kickout(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint32_t valid_name_len = params[1].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[1].memref.size;
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	// read user name
	uint8_t *username = TEE_Malloc(valid_name_len+8, TEE_MALLOC_FILL_ZERO);
	if(username == NULL){
		TEE_Free(session_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(username, params[1].memref.buffer, valid_name_len+1);
	// check session id
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	// get user info
	user_info_t *target_user = d3_core_get_user_by_name(user_info, username);
	if(target_user == NULL){
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_check_user_action_perm(user, target_user, ACTION_PERMISSON_KICOOUT)){
		//EMSG("D3TrustedCore: User [%s] has no permission to kickout user [%s]!", user->username, target_user->username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	// kick out user
	if(d3_core_kickout_user(&session, target_user)){
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	} else{
		IMSG("D3TrustedCore: User [%s] kickout by [%s]!", target_user->username, user->username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_user_passwd(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// get session, old password and new password
	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint32_t valid_old_passwd_len = params[1].memref.size > MAX_PASSWORD_LEN ? MAX_PASSWORD_LEN : params[1].memref.size;
	uint32_t valid_new_passwd_len = params[2].memref.size > MAX_PASSWORD_LEN ? MAX_PASSWORD_LEN : params[2].memref.size;
	// read session id
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(session_id, params[0].memref.buffer, valid_session_id_len);
	// read old password
	uint8_t *old_passwd = TEE_Malloc(valid_old_passwd_len+8, TEE_MALLOC_FILL_ZERO);
	if(old_passwd == NULL){
		TEE_Free(session_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(old_passwd, params[1].memref.buffer, valid_old_passwd_len);
	// read new password
	uint8_t *new_passwd = TEE_Malloc(valid_new_passwd_len+8, TEE_MALLOC_FILL_ZERO);
	if(new_passwd == NULL){
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	TEE_MemMove(new_passwd, params[2].memref.buffer, valid_new_passwd_len);
	if(strlen(new_passwd) < MIN_PASSWORD_LEN){
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		return TEE_ERROR_GENERIC;
	}
	//IMSG("D3TrustedCore: Change password for %s (%s -> %s)", session_id, old_passwd, new_passwd);

	// check session id
	session_t *target_session = NULL;
	if(d3_core_check_valid_session(session, session_id, &target_session) != 0){
		//EMSG("D3TrustedCore: Auth session_id failed, session not found!");
		TEE_Free(session_id);
		return TEE_ERROR_GENERIC;
	}
	// get user info
	user_info_t *user = target_session->user_info;
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_PASSWD)){
		//EMSG("D3TrustedCore: User [%s] has no permission to change password!", user->username);
		TEE_Free(session_id);
		return TEE_ERROR_GENERIC;
	}
	// hash and check old password (hexlify)
	uint8_t *old_passwd_hash_hex = TEE_Malloc(TEE_SHA256_HASH_SIZE*2+1, TEE_MALLOC_FILL_ZERO);
	if(old_passwd_hash_hex == NULL){
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	if(d3_core_sha256_and_hexlify(old_passwd, strlen(old_passwd), old_passwd_hash_hex, TEE_SHA256_HASH_SIZE*2) != 0){
		//EMSG("D3TrustedCore: Hash old password failed!");
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		TEE_Free(old_passwd_hash_hex);
		return TEE_ERROR_GENERIC;
	}
	if(TEE_MemCompare(user->password, old_passwd_hash_hex, TEE_SHA256_HASH_SIZE*2+1) != 0){
		//EMSG("D3TrustedCore: Old password not match!");
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		TEE_Free(old_passwd_hash_hex);
		return TEE_ERROR_GENERIC;		
	}
	// hash new password (hexlify)
	uint8_t *new_passwd_hash_hex = TEE_Malloc(TEE_SHA256_HASH_SIZE*2+1, TEE_MALLOC_FILL_ZERO);
	if(new_passwd_hash_hex == NULL){
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		TEE_Free(old_passwd_hash_hex);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	if(d3_core_sha256_and_hexlify(new_passwd, strlen(new_passwd), new_passwd_hash_hex, TEE_SHA256_HASH_SIZE*2) != 0){
		//EMSG("D3TrustedCore: Hash new password failed!");
		TEE_Free(session_id);
		TEE_Free(old_passwd);
		TEE_Free(new_passwd);
		TEE_Free(old_passwd_hash_hex);
		TEE_Free(new_passwd_hash_hex);
		return TEE_ERROR_GENERIC;
	}
	// update user info
	memset(user->password, 0, MAX_PASSWORD_LEN+8);
	TEE_MemMove(user->password, new_passwd_hash_hex, TEE_SHA256_HASH_SIZE*2+1);
	// release
	TEE_Free(session_id);
	TEE_Free(old_passwd);
	TEE_Free(new_passwd);
	TEE_Free(old_passwd_hash_hex);
	TEE_Free(new_passwd_hash_hex);
	return TEE_SUCCESS;
}

static TEE_Result d3_get_user_list(uint32_t param_types, TEE_Param params[4]){
	#define MODE_ALL 0
	#define MODE_NORMAL 1
	#define MODE_DISABLED 2
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, // session id
						   TEE_PARAM_TYPE_VALUE_INPUT, // max user count | mode
						   TEE_PARAM_TYPE_VALUE_OUTPUT, // user count
						   TEE_PARAM_TYPE_MEMREF_OUTPUT); // user list

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	if (params[3].memref.size < params[1].value.a * sizeof(user_info_out_t)){
		//EMSG("D3TrustedCore: User list buffer too small!");	
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// get session
	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	// read session id
	uint8_t session_id[HTTP_SESSION_LEN+8] = {0};
	TEE_MemMove(session_id, params[0].memref.buffer, valid_session_id_len);
	uint32_t max_user_count = params[1].value.a;
	uint32_t mode = params[1].value.b;
	// check session id
	if(d3_core_check_valid_session(session, session_id, NULL) != 0){
		//EMSG("D3TrustedCore: Auth session_id failed, session not found!");
		//TEE_Free(session_id);
		return TEE_ERROR_GENERIC;
	}
	// get user list
	uint32_t count = 0;
	user_info_out_t *user_list = NULL;
	switch (mode)
	{
		case MODE_ALL:{
			uint32_t count1 = 0;
			user_info_out_t *user_list1 = NULL;
			if(user_info){
				if(d3_core_get_user_list(user_info, &count1, &user_list1) != 0){
					//EMSG("D3TrustedCore: Get normal user list failed!");
					if(user_list1) TEE_Free(user_list1);
					return TEE_ERROR_GENERIC;
				}
			}
			uint32_t count2 = 0;
			user_info_out_t *user_list2 = NULL;
			if(user_info_disabled){
				if(d3_core_get_user_list(user_info_disabled, &count2, &user_list2) != 0){
					//EMSG("D3TrustedCore: Get disabled user list failed!");
					if(user_list1) TEE_Free(user_list1);
					if(user_list2) TEE_Free(user_list2);
					return TEE_ERROR_GENERIC;
				}
			}
			// Merge user lists
			if(count1 && count2 && user_list1 && user_list2){	
				count = count1 + count2;
				user_list = TEE_Malloc(count*sizeof(user_info_out_t), TEE_MALLOC_FILL_ZERO);
				if(user_list == NULL){
					//TEE_Free(session_id);
					TEE_Free(user_list1);
					TEE_Free(user_list2);
					return TEE_ERROR_OUT_OF_MEMORY;
				}
				TEE_MemMove(user_list, user_list1, count1*sizeof(user_info_out_t));
				TEE_MemMove(user_list+count1, user_list2, count2*sizeof(user_info_out_t));
				TEE_Free(user_list1);
				TEE_Free(user_list2);
			} else if(count1 && user_list1){
				count = count1;
				user_list = user_list1;
			} else if(count2 && user_list2){
				count = count2;
				user_list = user_list2;
			} else {
				count = 0;
				user_list = NULL;
			}
			break;
		}
		case MODE_NORMAL:{
			if(d3_core_get_user_list(user_info, &count, &user_list) != 0){
				//EMSG("D3TrustedCore: Get normal user list failed!");
				return TEE_ERROR_GENERIC;
			}
			break;
		}
		case MODE_DISABLED:{
			if(d3_core_get_user_list(user_info, &count, &user_list) != 0){
				//EMSG("D3TrustedCore: Get disabled user list failed!");
				return TEE_ERROR_GENERIC;
			}
			break;
		}
		default:{
			//EMSG("D3TrustedCore: Get user list failed, mode error!");
			return TEE_ERROR_GENERIC;
		}
	}
	uint32_t count_to_copy = count > max_user_count ? max_user_count : count;
	if(count > 0){
		params[2].value.a = count_to_copy;
		TEE_MemMove(params[3].memref.buffer, user_list, count_to_copy * sizeof(user_info_out_t));
		TEE_Free(user_list);
	} else{
		params[2].value.a = 0;
	}
	return TEE_SUCCESS;
}

static TEE_Result d3_user_enable(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// get valid session id length
	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint32_t valid_name_len = params[1].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[1].memref.size;
	// read session id
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	// read user name
	uint8_t *username = TEE_Malloc(valid_name_len+8, TEE_MALLOC_FILL_ZERO);
	if(username == NULL){
		TEE_Free(session_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(username, params[1].memref.buffer, valid_name_len+1);
	// check session id
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	// move user info
	user_info_t *target = d3_core_get_user_by_name(user_info_disabled, username);
	if(target == NULL){
		//EMSG("D3TrustedCore: User %s not found!", username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_check_user_action_perm(user, target, ACTION_PERMISSON_ENABLE)){
		//EMSG("D3TrustedCore: User %s has no permission to enable user %s!", user->username, target->username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	target = d3_core_move_user_by_name(&user_info_disabled, &user_info, username);
	if(target == NULL){
		//EMSG("D3TrustedCore: Move user failed!");
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	IMSG("D3TrustedCore: User [%s] enabled by [%s].", target->username, user->username);
	target->magic = USER_MAGIC_NORMAL;
	TEE_Free(session_id);
	TEE_Free(username);
	return TEE_SUCCESS;
}

static TEE_Result d3_user_disable(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	// get valid session id length
	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint32_t valid_name_len = params[1].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[1].memref.size;
	// read session id
	uint8_t *session_id = TEE_Malloc(valid_session_id_len+8, TEE_MALLOC_FILL_ZERO);
	if(session_id == NULL){
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	// read user name
	uint8_t *username = TEE_Malloc(valid_name_len+8, TEE_MALLOC_FILL_ZERO);
	if(username == NULL){
		TEE_Free(session_id);
		return TEE_ERROR_OUT_OF_MEMORY;
	}
	strncpy(username, params[1].memref.buffer, valid_name_len+1);
	// check session id
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	// check permission
	user_info_t *target = d3_core_get_user_by_name(user_info, username);
	if(target == NULL){
		//EMSG("D3TrustedCore: User %s not found!", username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_check_user_action_perm(user, target, ACTION_PERMISSON_DISABLE)){
		//EMSG("D3TrustedCore: User %s has no permission to disable user %s!", user->username, target->username);
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	// move user info
	target = d3_core_move_user_by_name(&user_info, &user_info_disabled, username);
	if(target == NULL){
		//EMSG("D3TrustedCore: Move user failed!");
		TEE_Free(session_id);
		TEE_Free(username);
		return TEE_ERROR_GENERIC;
	}
	IMSG("D3TrustedCore: User [%s] disabled by [%s]!", target->username, user->username);
	target->magic = USER_MAGIC_DISABLED;
	TEE_Free(session_id);
	TEE_Free(username);
	return TEE_SUCCESS;
}

static TEE_Result d3_user_reset(uint32_t param_types, TEE_Param params[4]){
	if(TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT 
		|| TEE_PARAM_TYPE_GET(param_types, 1) != TEE_PARAM_TYPE_MEMREF_INPUT){
		return TEE_ERROR_BAD_PARAMETERS;
	}

	// get valid session id length
	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	uint32_t valid_name_len = params[1].memref.size > MAX_USERNAME_LEN ? MAX_USERNAME_LEN : params[1].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	char username[MAX_USERNAME_LEN+8] = {0};
	strncpy(username, params[1].memref.buffer, valid_name_len+1);

	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}

	//d3_core_log_user_obj(user_info);
	//d3_core_log_user_obj(user_info_disabled);

	user_info_t *target_user = NULL;
	uint32_t user_is_disabled = 0;
	if((target_user = d3_core_get_user_by_name(user_info, username)) != NULL){
		user_is_disabled = 0;
	} else if((target_user = d3_core_get_user_by_name(user_info_disabled, username)) != NULL){
		user_is_disabled = 1;
	} else{
		//EMSG("D3TrustedCore: User %s not found!", username);
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_check_user_action_perm(user, target_user, ACTION_PERMISSON_RESET)){
		//EMSG("D3TrustedCore: User %s has no permission to reset user %s!", user->username, target_user->username);
		return TEE_ERROR_GENERIC;
	}
	#define RESET_DEFAULT_PASSWD "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
	// move user info
	//IMSG("[*] d3_user_reset: target user %s ptr %p", target_user->username, target_user);

	uint32_t uid = target_user->uid;
	uint32_t type = target_user->type;
	user_info_t *new_user_ptr = NULL;
	uint32_t enable_face_id = 0;
	vec_float *face_data = NULL;
	if(user_is_disabled){
		d3_core_remove_user_info(&user_info_disabled, target_user->username);
		if(TEE_PARAM_TYPE_GET(param_types, 2) == TEE_PARAM_TYPE_MEMREF_INPUT
			&& params[2].memref.size == FACE_DATA_SIZE_BYTES && params[2].memref.buffer != NULL){
			face_data = (vec_float *)TEE_Malloc(FACE_DATA_SIZE_BYTES, TEE_MALLOC_FILL_ZERO); //  reuse freed memory
			TEE_MemMove(face_data, params[2].memref.buffer, FACE_DATA_SIZE_BYTES);
			enable_face_id = 1;
		}
		if(d3_core_add_user_info(&user_info_disabled, USER_MAGIC_DISABLED, uid, type, username, RESET_DEFAULT_PASSWD)){
			return TEE_ERROR_GENERIC;
		}
		if(enable_face_id){
			d3_core_enable_user_face_id(user_info_disabled, username, face_data, 0);
		} else{
			d3_core_disable_user_face_id(user_info_disabled, username);
		}
		new_user_ptr = d3_core_get_user_by_name(user_info_disabled, username);
		session_t *alive_session = session;
		while (alive_session){
			if (alive_session->user_info->uid == uid){  // bypass this check
				alive_session->user_info = new_user_ptr;
				break;
			}
			alive_session = alive_session->next;
		}
	} else{
		d3_core_remove_user_info(&user_info, target_user->username);
		if(TEE_PARAM_TYPE_GET(param_types, 2) == TEE_PARAM_TYPE_MEMREF_INPUT
			&& params[2].memref.size == FACE_DATA_SIZE_BYTES && params[2].memref.buffer != NULL){
			face_data = (vec_float *)TEE_Malloc(FACE_DATA_SIZE_BYTES, TEE_MALLOC_FILL_ZERO);
			TEE_MemMove(face_data, params[2].memref.buffer, FACE_DATA_SIZE_BYTES);
			enable_face_id = 1;
		}
		if(d3_core_add_user_info(&user_info, USER_MAGIC_NORMAL, uid, type, username, RESET_DEFAULT_PASSWD)){
			return TEE_ERROR_GENERIC;
		}
		if(enable_face_id){
			d3_core_enable_user_face_id(user_info, username, face_data, 0);
		} else{
			d3_core_disable_user_face_id(user_info, username);
		}
		new_user_ptr = d3_core_get_user_by_name(user_info, username);
		session_t *alive_session = session;
		while (alive_session){
			if (alive_session->uid == uid){
				alive_session->user_info = new_user_ptr;
				break;
			}
			alive_session = alive_session->next;
		}
	}
	IMSG("[*] D3TrustedCore: User [%s] reset by [%s]!", username, user->username);
	
	//d3_core_log_user_obj(user_info);
	//d3_core_log_user_obj(user_info_disabled);

	return TEE_SUCCESS;
}

static TEE_Result d3_create_sec_file(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INOUT);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_CREATE_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to create sec file!", user->username);
		return TEE_ERROR_GENERIC;
	}

	uint32_t filename_len = params[1].memref.size;
	char filename[MAX_FILE_NAME+8] = {0};
	if(filename_len == 0 || filename_len > MAX_FILE_NAME){
		//EMSG("D3TrustedCore: Invalid filename!");
		return TEE_ERROR_GENERIC;
	}
	if(params[1].memref.buffer == NULL){
		//EMSG("D3TrustedCore: Invalid filename ptr!");
		return TEE_ERROR_GENERIC;
	}
	strncpy(filename, params[1].memref.buffer, filename_len+1);

	uint32_t data_sz = params[2].memref.size;
	if(data_sz > MAX_FILE_DATA){
		//EMSG("D3TrustedCore: Invalid data size!");
		return TEE_ERROR_GENERIC;
	}
	if(params[2].memref.buffer == NULL){
		//EMSG("D3TrustedCore: Invalid data ptr!");
		return TEE_ERROR_GENERIC;
	}
	uint8_t *data = (uint8_t *)params[2].memref.buffer;

	uint32_t parent_id = params[3].value.a;
	if(parent_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid parent id!");
		return TEE_ERROR_GENERIC;
	}

	uint32_t ext_id_out = ~0;
	uint32_t res = d3_core_create_secure_file(filename, parent_id, user->uid, data, data_sz, &ext_id_out);
	if(res == 2){ // filename conflict
		//EMSG("D3TrustedCore: File [%s] already exists!", filename);
		return TEE_ERROR_ACCESS_CONFLICT;
	}
	if(res == 3){ // no space
		//EMSG("D3TrustedCore: No space to create file [%s]!", filename);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}
	if(res != 0){
		//EMSG("D3TrustedCore: Fail to create secure file [%s]!", filename);
		return TEE_ERROR_GENERIC;
	}
	if(ext_id_out != ~0){
		params[3].value.b = ext_id_out;
	}
	IMSG("D3TrustedCore: User [%s] created file [%s]!", user->username, filename);
	return TEE_SUCCESS;
}

static TEE_Result d3_update_sec_file(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT, // ext_id
						   TEE_PARAM_TYPE_MEMREF_INPUT, // file_data
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_WRITE_FILE)){
		return TEE_ERROR_GENERIC;
	}
	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	uint32_t data_sz = params[2].memref.size;
	if(data_sz > MAX_FILE_DATA){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	uint8_t *data = (uint8_t *)params[2].memref.buffer;
	uint32_t res = d3_core_update_secure_file(ext_id, data, data_sz);
	if(res != 0){
		return TEE_ERROR_GENERIC;
	}
	IMSG("D3TrustedCore: User [%s] update file (ext_id = %d).", user->username, ext_id);
	return TEE_SUCCESS;
}

static TEE_Result d3_delete_sec_file(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_DELETE_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to delete sec file!", user->username);
		return TEE_ERROR_GENERIC;
	}

	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid file id!");
		return TEE_ERROR_GENERIC;
	}
	#define DELETE_MODE_ERASE 1
	#define DELETE_MODE_UNLINK 0
	uint32_t del_mode = params[1].value.b;
	uint32_t ret;
	if(del_mode == DELETE_MODE_ERASE){
		ret = d3_core_delete_secure_file(ext_id, 1);
	} else{
		ret = d3_core_delete_secure_file(ext_id, 0);
	}

	if(ret != 0){
		//EMSG("D3TrustedCore: Delete secure file (ext_id = %d, mode = %d) failed!", ext_id, del_mode);
		return TEE_ERROR_GENERIC;
	} else{
		IMSG("D3TrustedCore: Delete secure file (ext_id = %d, mode = %d).", ext_id, del_mode);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_get_sec_file_info(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT, // file_info_t
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_LIST_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to get sec file info!", user->username);
		return TEE_ERROR_GENERIC;
	}
	file_info_t *file_info = (file_info_t *)params[2].memref.buffer;
	memset(file_info, 0, sizeof(file_info_t));
	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid file id!");
		return TEE_ERROR_GENERIC;
	}
	uint32_t res = d3_core_get_sec_file_info(ext_id, file_info);
	if(res == 0){
		params[2].memref.size = sizeof(file_info_t);
		IMSG("D3TrustedCore: Get secure file (ext_id = %d) info.", ext_id);
		return TEE_SUCCESS;
	} else if(res == 2){
		//IMSG("D3TrustedCore: Secure file (ext_id = %d) hash error!", ext_id);
		return TEE_ERROR_CORRUPT_OBJECT;
	} else{
		//EMSG("D3TrustedCore: Get secure file info failed!");
		return TEE_ERROR_GENERIC;
	}
}

static TEE_Result d3_read_sec_file(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT, // file_info_t
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_READ_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to read sec file info!", user->username);
		return TEE_ERROR_GENERIC;
	}
	char *file_data = (char *)params[2].memref.buffer;
	uint32_t file_data_sz = 0;
	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid file id!");
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_read_sec_file(ext_id, file_data, params[2].memref.size, &file_data_sz)){
		//EMSG("D3TrustedCore: Read secure file (ext_id = %d) failed!", ext_id);
		return TEE_ERROR_GENERIC;
	} else{
		params[2].memref.size = file_data_sz;
		IMSG("D3TrustedCore: Read secure file (ext_id = %d).", ext_id);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_get_secfs_slots_info(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT, // uint8_t[]
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_LIST_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to list sec fs slot!", user->username);
		return TEE_ERROR_GENERIC;
	}
	uint8_t *slot_info = (char *)params[1].memref.buffer;
	if(params[1].memref.size < MAX_FILE_COUNT*sizeof(uint8_t)){
		//EMSG("D3TrustedCore: Invalid slot info buffer size!");
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_get_secfs_slots_info(slot_info, MAX_FILE_COUNT)){
		//EMSG("D3TrustedCore: Get secure file system slot info failed!");
		return TEE_ERROR_GENERIC;
	} else{
		params[1].memref.size = MAX_FILE_COUNT*sizeof(uint8_t);
		IMSG("D3TrustedCore: Get secure file system slots info.");
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_create_sec_dir(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_INPUT, // dir name
						   TEE_PARAM_TYPE_VALUE_INPUT, // parent dir id
						   TEE_PARAM_TYPE_VALUE_OUTPUT); // ext_id_out

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_CREATE_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to create dir", user->username);
		return TEE_ERROR_GENERIC;
	}
	if(params[1].memref.size > MAX_DIR_NAME || params[1].memref.size == 0){
		//EMSG("D3TrustedCore: Invalid dir name length!");
		return TEE_ERROR_GENERIC;
	}

	uint32_t valid_dir_name_len = params[1].memref.size;
	char dir_name[MAX_DIR_NAME+8] = {0};
	strncpy(dir_name, params[1].memref.buffer, valid_dir_name_len);
	uint32_t parent_dir_id = params[2].value.a;
	uint32_t ext_id_out = ~0;
	uint32_t res = d3_core_create_secure_dir(dir_name, parent_dir_id, user->uid, &ext_id_out);
	if(res == 2){ // dir name conflict
		//EMSG("D3TrustedCore: Dir %s already exists!", dir_name);
		return TEE_ERROR_ACCESS_CONFLICT;
	}
	if(res == 3){ // no space
		//EMSG("D3TrustedCore: No space to create dir %s!", dir_name);
		return TEE_ERROR_STORAGE_NOT_AVAILABLE;
	}
	if(res != 0){
		//EMSG("D3TrustedCore: Create secure dir failed!");
		return TEE_ERROR_GENERIC;
	}
	if(ext_id_out != ~0){
		params[3].value.a = ext_id_out;
	}
	IMSG("D3TrustedCore: Create secure dir [%s].", dir_name);
	return TEE_SUCCESS;
}

static TEE_Result d3_delete_sec_dir(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT, // ext_id | recursive
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_DELETE_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to delete dir", user->username);
		return TEE_ERROR_GENERIC;
	}
	uint32_t ext_id = params[1].value.a;
	uint32_t recursive = params[1].value.b;
	uint32_t res = d3_core_delete_secure_dir(ext_id, recursive);
	if(res != 0){
		//EMSG("D3TrustedCore: Delete secure dir failed!");
		return TEE_ERROR_GENERIC;
	} else{
		IMSG("D3TrustedCore: Delete secure dir (ext_id = %d).", ext_id);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_get_sec_dir_info(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT, // dir_info_t
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_READ_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to get dir info", user->username);
		return TEE_ERROR_GENERIC;
	}
	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid dir ext_id!");
		return TEE_ERROR_GENERIC;
	}
	dir_info_t *dir_info = (dir_info_t *)params[2].memref.buffer;
	if(params[2].memref.size < sizeof(dir_info_t)){
		//EMSG("D3TrustedCore: Invalid dir_info_t size!");
		return TEE_ERROR_GENERIC;
	}
	if(d3_core_get_sec_dir_info(ext_id, dir_info)){
		//EMSG("D3TrustedCore: Get secure dir info failed!");
		return TEE_ERROR_GENERIC;
	} else{
		params[2].memref.size = sizeof(dir_info_t);
		EMSG("D3TrustedCore: Get secure dir info (ext_id = %d).", ext_id);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_rename_sec_file(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT, // ext_id
						   TEE_PARAM_TYPE_MEMREF_INPUT, // new_name
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t valid_session_id_len = params[0].memref.size > HTTP_SESSION_LEN ? HTTP_SESSION_LEN : params[0].memref.size;
	char session_id[HTTP_SESSION_LEN+8] = {0};
	strncpy(session_id, params[0].memref.buffer, valid_session_id_len+1);
	session_t *tmp_session = NULL;
	user_info_t *user = NULL;
	if(d3_core_check_valid_session(session, session_id, &tmp_session) != 0){
		//EMSG("D3TrustedCore: Session_id check failed!");
		return TEE_ERROR_GENERIC;
	} else{
		user = tmp_session->user_info;
	}
	if(d3_core_check_user_action_perm(user, user, ACTION_PERMISSON_WRITE_FILE)){
		//EMSG("D3TrustedCore: User %s has no permission to re rename file", user->username);
		return TEE_ERROR_GENERIC;
	}
	uint32_t ext_id = params[1].value.a;
	if(ext_id >= MAX_FILE_COUNT){
		//EMSG("D3TrustedCore: Invalid file ext_id!");
		return TEE_ERROR_GENERIC;
	}
	uint32_t new_name_len = params[2].memref.size;
	char new_name[MAX_FILE_NAME+8] = {0};
	if(new_name_len > MAX_FILE_NAME || params[2].memref.buffer == NULL){
		//EMSG("D3TrustedCore: Invalid new file name!");
		return TEE_ERROR_GENERIC;
	}
	TEE_MemMove(new_name, params[2].memref.buffer, new_name_len);
	if(d3_core_rename_sec_file(ext_id, new_name)){
		//EMSG("D3TrustedCore: Rename secure file failed!");
		return TEE_ERROR_GENERIC;
	} else{
		EMSG("D3TrustedCore: Rename secure file (ext_id = %d, name = %d).", ext_id, new_name);
		return TEE_SUCCESS;
	}
}

static TEE_Result d3_check_alive(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	params[0].value.a = 0x6b6f6d69; // "imok"

	return TEE_SUCCESS;
}

static TEE_Result d3_calc_sha256(uint32_t param_types, TEE_Param params[4]){
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint8_t *data = (uint8_t *)params[0].memref.buffer;
	uint32_t data_len = params[0].memref.size;
	if(data_len > 0x40000000){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	uint8_t *hash = (uint8_t *)params[1].memref.buffer;
	uint32_t hash_len = params[1].memref.size;
	if(hash_len < TEE_SHA256_HASH_SIZE){
		return TEE_ERROR_BAD_PARAMETERS;
	}
	hash_len = TEE_SHA256_HASH_SIZE;
	if(d3_core_sha256(data, data_len, hash) != TEE_SHA256_HASH_SIZE){
		return TEE_ERROR_GENERIC;
	}
	return TEE_SUCCESS;
}
// *************************************************************************

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx; /* Unused parameter */

	switch (cmd_id) {
		case TA_D3_CMD_DEBUG_LOG:
			return test_debug_log(param_types, params);

		case TA_D3_CMD_AUTH_USER_PASSWD:
			return d3_auth_user_passwd(param_types, params);
		case TA_D3_CMD_AUTH_USER_FACE_ID:
			return d3_auth_user_face_id(param_types, params);
		case TA_D3_CMD_AUTH_SESSION_ID:
			return d3_auth_session_id(param_types, params);

		case TA_D3_CMD_GET_USER_INFO:
			return d3_get_user_info(param_types, params); 
		case TA_D3_CMD_GET_USER_LIST:
			return d3_get_user_list(param_types, params);

		case TA_D3_CMD_USER_PASSWD:
			return d3_user_passwd(param_types, params);
		case TA_D3_CMD_USER_ENABLE:
			return d3_user_enable(param_types, params);
		case TA_D3_CMD_USER_DISABLE:
			return d3_user_disable(param_types, params);
		case TA_D3_CMD_USER_LOGOUT:
			return d3_user_logout(param_types, params);
		case TA_D3_CMD_USER_KICKOUT:
			return d3_user_kickout(param_types, params);
		case TA_D3_CMD_USER_RESET:
			return d3_user_reset(param_types, params);

		case TA_D3_CMD_CREATE_SEC_FILE:
			return d3_create_sec_file(param_types, params);
		case TA_D3_CMD_DELETE_SEC_FILE:
			return d3_delete_sec_file(param_types, params);
		case TA_D3_CMD_GET_SEC_FILE_INFO:
			return d3_get_sec_file_info(param_types, params);
		case TA_D3_CMD_READ_SEC_FILE:
			return d3_read_sec_file(param_types, params);
		case TA_D3_CMD_UPDATE_SEC_FILE:
			return d3_update_sec_file(param_types, params);
		case TA_D3_CMD_RENAME_SEC_FILE:
			return d3_rename_sec_file(param_types, params);

		case TA_D3_CMD_GET_SECFS_SLOTS_INFO:
			return d3_get_secfs_slots_info(param_types, params);
		case TA_D3_CMD_CREATE_SEC_DIR:
			return d3_create_sec_dir(param_types, params);
		case TA_D3_CMD_DELETE_SEC_DIR:
			return d3_delete_sec_dir(param_types, params);
		case TA_D3_CMD_GET_SEC_DIR_INFO:
			return d3_get_sec_dir_info(param_types, params);

		case TA_D3_CMD_CHECK_ALIVE:
			return d3_check_alive(param_types, params);
		case TA_D3_CMD_CALC_SHA256:
			return d3_calc_sha256(param_types, params);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}
