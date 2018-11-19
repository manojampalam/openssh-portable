#include <Windows.h>

#define BUFSIZE 4096 

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;


void CreateChildProcess(void);
void ErrorExit(PTSTR str) {};

void CreateChildProcess()
// Create a child process that uses the previously created pipes for STDIN and STDOUT.
{
	char szCmdline[] = "C:\\temp\\AKVBroker\\bin\\Debug\\Microsoft.Azure.SSHKeyAgent.exe";
	//TEXT("C:\\Temp\\sample\\csharpapp\\csharpapp\\bin\\Debug\\csharpapp.exe");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	// Set up members of the PROCESS_INFORMATION structure. 

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));

	// Set up members of the STARTUPINFO structure. 
	// This structure specifies the STDIN and STDOUT handles for redirection.

	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	// Create the child process. 

	bSuccess = CreateProcessA(NULL,
		szCmdline,     // command line 
		NULL,          // process security attributes 
		NULL,          // primary thread security attributes 
		TRUE,          // handles are inherited 
		0,             // creation flags 
		NULL,          // use parent's environment 
		NULL,          // use parent's current directory 
		&siStartInfo,  // STARTUPINFO pointer 
		&piProcInfo);  // receives PROCESS_INFORMATION 

			       // If an error occurs, exit the application. 
	if (!bSuccess)
		ErrorExit(TEXT("CreateProcess"));
	else
	{
		// Close handles to the child process and its primary thread.
		// Some applications might keep these handles to monitor the status
		// of the child process, for example. 

		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
	}
}

int start_managed_worker() {
	SECURITY_ATTRIBUTES saAttr;
	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;
	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
		ErrorExit(TEXT("StdoutRd CreatePipe"));
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
		ErrorExit(TEXT("Stdout SetHandleInformation"));
	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
		ErrorExit(TEXT("Stdin CreatePipe"));
	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
		ErrorExit(TEXT("Stdin SetHandleInformation"));

	// Create the child process. 
	CreateChildProcess();

	CloseHandle(g_hChildStd_OUT_Wr);
	CloseHandle(g_hChildStd_IN_Rd);


	return 0;
}

static int save_entry(char* key, char* buf, int buf_len) {
	DWORD dwWritten, dwRead;
	BOOL bSuccess = FALSE;
	char type = 1, ret= 0;

	bSuccess = WriteFile(g_hChildStd_IN_Wr, &type, 1, &dwWritten, NULL);
	bSuccess = WriteFile(g_hChildStd_IN_Wr, &buf_len, 4, &dwWritten, NULL);
	bSuccess = WriteFile(g_hChildStd_IN_Wr, buf, buf_len, &dwWritten, NULL);

	DWORD siz_recv;
	bSuccess = ReadFile(g_hChildStd_OUT_Rd, &ret, 1, &dwRead, NULL);
	return 0;
}

static int get_entry(char* key, char** buf, int* buf_len) {
	DWORD dwWritten, dwRead;
	BOOL bSuccess = FALSE;
	char type = 2, ret = 0;

	bSuccess = WriteFile(g_hChildStd_IN_Wr, &type, 1, &dwWritten, NULL);

	bSuccess = ReadFile(g_hChildStd_OUT_Rd, &ret, 1, &dwRead, NULL);
	bSuccess = ReadFile(g_hChildStd_OUT_Rd, buf_len, 4, &dwRead, NULL);
	*buf = malloc(*buf_len);
	bSuccess = ReadFile(g_hChildStd_OUT_Rd, *buf, *buf_len, &dwRead, NULL);

	return 0;
}



#define BPTR (entry + offset)

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
	return -1; //not supported yet
}

int
delete_all(struct agent_connection* con) {
	return delete_identity(NULL, con);
}
