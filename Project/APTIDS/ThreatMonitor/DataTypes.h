#define MAX_BUF_LEN 65532
#define MAX_BUFFER_LEN 65532
#define MAX_KEY_LEN 255
#define MAX_REG_THREADS 10


#define LOG_TYPE_REGISTRY 1
#define LOG_TYPE_SERVICE 2

typedef struct RegKey{
	PCHAR stlpMainKey;
	PCHAR stlpKey;
}REGKEY, *PREGKEY;


