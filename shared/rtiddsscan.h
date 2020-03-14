
#include <sys/time.h>   // Req. for struct timeval - see man gettimeofday



#define DDSSCAN_STRING_MAX  100

struct RTIDDSScanSummary {
    // Virus knowledge base
    char                engine_version[30];
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


