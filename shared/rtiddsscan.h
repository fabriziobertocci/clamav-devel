
#include <sys/time.h>   // Req. for struct timeval - see man gettimeofday



#define DDSSCAN_VERSION_STRING_MAX  30

struct RTIDDSScanSummary {
    // Virus knowledge base
    char                engine_version[DDSSCAN_VERSION_STRING_MAX+1];
    unsigned long       engine_viruscount;
    unsigned long       engine_lastupdate;                      // UTC
    
    // Scan Result
    unsigned long       res_scanned_files;
    unsigned long       res_scanned_dirs;
    unsigned long       res_infected_files;
    unsigned long       res_errors;
    struct timeval      res_run_time;       // Time required to run the scan
};


/* Returns 0 if an error occurred during initialization */
int RTIDDSScan_init(int verbose, char *dwName);

void RTIDDSScan_finalize(void);

void RTIDDSScan_start(void);
void RTIDDSScan_done(const struct RTIDDSScanSummary *scanSummary);

void RTIDDSScan_fileScanINFECTED(const char *filename, const char *virname);
void RTIDDSScan_fileScanOK(const char *filename);
void RTIDDSScan_fileScanERROR(const char *filename, const char *error);

// Invoked directly from the libfreshclam before and after updating each 
// database file
int RTIDDSScan_onDatabaseUpdated(int op, 
        const char *dbName, 
        const char *version,
        int threatCount,
        const char *errMsg,
        void *arg);


