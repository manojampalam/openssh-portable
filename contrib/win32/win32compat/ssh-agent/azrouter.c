#include <Windows.h>




#define BPTR (entry + offset)

static char g_buf[1024 * 10];
static int g_buf_len = 0;
static int save_entry(char* key, char* buf, int buf_len) {

	g_buf_len = buf_len;
	memcpy(g_buf, buf, buf_len);
	return 0;
}

static int get_entry(char* key, char** buf, int* buf_len) {
	char* ret = malloc(g_buf_len);
	*buf_len = g_buf_len;
	memcpy(ret, g_buf, g_buf_len);
	*buf = ret;
	return 0;
}


int add_identity(char* thumbprint, char* pubkey_blob, int pubkey_blob_len, char* blob, int blob_len,
	char* comment, int comment_len, char type, struct agent_connection* con)
{
	char entry[1024 * 10];
	// first 4 bytes len, next 4 bytes type
	int offset = 0;

	*(int*)BPTR = pubkey_blob_len;
	offset += 4;
	*(int*)BPTR = blob_len;
	offset += 4;
	*(int*)BPTR = comment_len;
	offset += 4;
	
	memcpy(BPTR, pubkey_blob, pubkey_blob_len);
	offset += pubkey_blob_len;
	memcpy(BPTR, blob, blob_len);
	offset += blob_len;
	memcpy(BPTR, comment, comment_len);
	offset += comment_len;

	if (save_entry(thumbprint, entry, offset) != 0)
		return -1;

	return 0;
}

void
decode_keyentry(char* entry, char** pubkey, int* pubkey_len, char**privkey, int* privkey_len, char** comment, int* comment_len)
{
	int offset = 0;

	*pubkey_len = *(int*)BPTR;
	offset += 4;
	*privkey_len = *(int*)BPTR;
	offset += 4;
	*comment_len = *(int*)BPTR;
	offset += 4;

	if (pubkey) {
		*pubkey = malloc(*pubkey_len);
		memcpy(*pubkey, BPTR, *pubkey_len);
	}
	offset += *pubkey_len;

	if (privkey) {
		*privkey = malloc(*privkey_len);
		memcpy(*privkey, BPTR, *privkey_len);
	}
	offset += *privkey_len;
	
	if (comment) {
		*comment = malloc(*comment_len);
		memcpy(*comment, BPTR, *comment_len);
	}
}

int
get_all_pubkeys(char* pubkey_blobs[32], int pubkey_blob_len[32], char* comments[32], int comment_len[32], struct agent_connection* con)
{
	memset(pubkey_blob_len, 0, sizeof(pubkey_blob_len));

	char* entry;
	int entry_len;
	int count = 0;

	if (g_buf_len == 0)
		return 0;

	{
		int pubkey_len, privkey_len, com_len;
		char *pubkey, *com;
		get_entry(NULL, &entry, &entry_len);
		decode_keyentry(entry, &pubkey, &pubkey_len, NULL, &privkey_len, &com, &com_len);
		pubkey_blobs[count] = pubkey;
		pubkey_blob_len[count] = pubkey_len;
		comments[count] = com;
		comment_len[count] = com_len;
 
		free(entry);
	}

	return 0;

}

int get_privkeyblob(char* thumbprint, char** blob, int* blob_len, struct agent_connection* con)
{
	char* entry;
	int entry_len;
	int pubkey_len, privkey_len, com_len;
	char *privkey;

	get_entry(NULL, &entry, &entry_len);
	decode_keyentry(entry, NULL, &pubkey_len, &privkey, &privkey_len, NULL, &com_len);
	*blob = privkey;
	*blob_len = privkey_len;

	return 0;

}


int
delete_identity(char* thumbprint, struct agent_connection* con) {
	g_buf_len = 0;
	return 0;
}

int
delete_all(struct agent_connection* con) {
	delete_identity(NULL, con);
}
