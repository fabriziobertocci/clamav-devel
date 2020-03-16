
// #define _GNU_SOURCE         // Req. for more 'sane' basename() and dirname()
#include <string.h>

#include <limits.h>
#include <stdlib.h>

#include <time.h>

#include <unistd.h>
#include <ndds/ndds_c.h>

#include "rtiddsscan.h"

#define RTIDDSSCAN_VERSION          "1.0a"

#define LOGPREFIX           "[RTIDDS] "
#define rtiddsscan_log(msg, ...)   if (theVerbose) fprintf(stdout, LOGPREFIX msg, ##__VA_ARGS__ )
#define rtiddsscan_err(msg, ...)   fprintf(stderr, LOGPREFIX msg, ##__VA_ARGS__ )


// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Globals (ugly, please don't judge!)
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
static RTIBool theVerbose;
static DDS_DomainParticipant * theDomainParticipant;
static DDS_DynamicDataWriter * theAVEventWriter;

static DDS_DynamicData * theAVEventInstance;  // An instance of CIM::AntiVirus::Event

const char * const CLIENTID_VENDOR_PRODUCT = "ClamAV";
static char CLIENTID_HOSTNAME[50];
static char CLIENTID_USERNAME[50];                      // Assigned in init()

#define LIFECYCLE_EVENT_START           1
#define LIFECYCLE_EVENT_COMPLETED       2
#define LIFECYCLE_EVENT_INTERRUPTED     3

#define FILESCAN_ACTION_ALLOWED         1
#define FILESCAN_ACTION_BLOCKED         2
#define FILESCAN_ACTION_DEFERRED        3
#define FILESCAN_ACTION_IGNORED         4
#define FILESCAN_ACTION_KILLED          5
#define FILESCAN_ACTION_ERROR           6

// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Local Utility Functions
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* {{{ _parseDataWriterName
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Parses the input string and break it into 2 components: the partLib::partName
 * and pubName::dwName.
 *
 * Places a pointer to the original string (that is modified) inside
 * ddsEntityOut. Do NOT free the returned strings.
 *
 * Returns RTI_TRUE if success, RTI_FALSE if the input string is not correctly
 * formatted (a detailed error message is printed).
 */
static RTIBool _parseDataWriterName(char *dwName, char *ddsEntityOut[2]) {
    char *ptr;
    ptr = strstr(dwName, "::");
    if (!ptr) {
        rtiddsscan_err("Invalid data writer name (cannot locate partLib)\n");
        return RTI_FALSE;
    }
    ptr += 2;  // Skip the '::'
    ptr = strstr(ptr, "::");
    if (!ptr) {
        rtiddsscan_err("Invalid data writer name (cannot locate partName)\n");
        return RTI_FALSE;
    }
    *ptr = '\0';
    ddsEntityOut[0] = dwName;
    ddsEntityOut[1] = ptr+2;
    return RTI_TRUE;
}

/* }}} */
/* {{{ _createDatawriter
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
static DDS_DynamicDataWriter * _createDatawriter(const char *dwName) {
    DDS_DynamicDataWriter * retVal = NULL;
    DDS_DataWriter *dw = DDS_DomainParticipant_lookup_datawriter_by_name(theDomainParticipant, dwName);
    if (!dw) {
        rtiddsscan_err("Failed to create writer '%s'\n", dwName);
        return NULL;
    }

    retVal = DDS_DynamicDataWriter_narrow(dw);
    if (!retVal) {
        rtiddsscan_err("Narrow on malaware writer failed\n");
        return NULL;
    }
    return retVal;
}

// }}}
/* {{{ _createAVEventInstance
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
static RTIBool _createAVEventInstance(void) {
    if (!theAVEventInstance) {
        theAVEventInstance = DDS_DynamicDataWriter_create_data_w_property(theAVEventWriter, &DDS_DYNAMIC_DATA_PROPERTY_DEFAULT);
        if (!theAVEventWriter) {
            rtiddsscan_err("Failed to create instance for AntiVirus topic\n");
            return RTI_FALSE;
        }
    }
    return RTI_TRUE;
}

// }}}
/* {{{ _setClientId
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Returns FALSE if an error occurred
 */
static RTIBool _setClientId(DDS_DynamicData *instance, const char *discrName) {
    char path[100];

    DDS_ReturnCode_t retCode;
    snprintf(path, 100, "%s.vendor_product", discrName);
    retCode = DDS_DynamicData_set_string(
                    instance,
                    path,
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    CLIENTID_VENDOR_PRODUCT);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set '%s' property: %d\n", path, retCode);
        return RTI_FALSE;
    }
    snprintf(path, 100, "%s.user", discrName);
    retCode = DDS_DynamicData_set_string(
                    instance,
                    path,
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    CLIENTID_USERNAME);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set '%s' property: %d\n", path, retCode);
        return RTI_FALSE;
    }
    snprintf(path, 100, "%s.dest.host", discrName);
    retCode = DDS_DynamicData_set_string(
                    instance,
                    path,
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    CLIENTID_HOSTNAME);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set '%s' property: %d\n", path, retCode);
        return RTI_FALSE;
    }

    return RTI_TRUE;
}

// }}}
/* {{{ _composeOperationEvent
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
static RTIBool _composeOperationEvent(int eventId) {
    DDS_ReturnCode_t retCode;

    if (!_createAVEventInstance()) {
        rtiddsscan_err("Failed to create AVScan event instance\n");
        return RTI_FALSE;
    }
    if (!_setClientId(theAVEventInstance, "operation")) {
        rtiddsscan_err("Failed to set client ID\n");
        return RTI_FALSE;
    }
    retCode = DDS_DynamicData_set_long(
                    theAVEventInstance,
                    "operation.action",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    eventId);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.action' property: %d\n", retCode);
        return RTI_FALSE;
    }
    retCode = DDS_DynamicData_set_ulong(
                    theAVEventInstance,
                    "operation.date.sec",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    (unsigned long)time(NULL));
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.date.sec' property: %d\n", retCode);
        return RTI_FALSE;
    }
    retCode = DDS_DynamicData_set_ulong(
                    theAVEventInstance,
                    "operation.date.nanosec",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    0);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.datetimestamp' property: %d\n", retCode);
        return RTI_FALSE;
    }
    return RTI_TRUE;
    return RTI_TRUE;
}

/* }}} */
/* {{{ _writeFileScanEvent
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
static RTIBool _writeFileScanEvent(const char *filename, const char *virname, const char *message, int actionId) {
    DDS_ReturnCode_t retCode;

    if (!_createAVEventInstance()) {
        return RTI_FALSE;
    }
    if (!_setClientId(theAVEventInstance, "scan")) {
        return RTI_FALSE;
    }

    // Sets file_path
    {
        char path[PATH_MAX];    // PATH_MAX is defined in limits.h
        // Convert the filename in absolute path
        if (!realpath(filename, path)) {
            rtiddsscan_err("Unable to convert relative file name '%s' in absolute path\n", filename);
            return RTI_FALSE;
        }
        retCode = DDS_DynamicData_set_string(
                        theAVEventInstance,
                        "scan.file_path",
                        DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                        path);
        if (retCode != DDS_RETCODE_OK) {
            rtiddsscan_err("Failed to set 'file_path' property: %d\n", retCode);
            return RTI_FALSE;
        }
    }

    // action
    retCode = DDS_DynamicData_set_long(
                    theAVEventInstance,
                    "scan.action",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    actionId);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'action' property: %d\n", retCode);
        return RTI_FALSE;
    }

    // Date
    {
        time_t tNow = time(NULL);
        retCode = DDS_DynamicData_set_ulong(
                        theAVEventInstance,
                        "scan.date.sec",
                        DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                        (unsigned long)tNow);
        if (retCode != DDS_RETCODE_OK) {
            rtiddsscan_err("Failed to set 'date' property: %d\n", retCode);
            return RTI_FALSE;
        }
        retCode = DDS_DynamicData_set_ulong(
                        theAVEventInstance,
                        "scan.date.nanosec",
                        DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                        0UL);
        if (retCode != DDS_RETCODE_OK) {
            rtiddsscan_err("Failed to set 'date' property: %d\n", retCode);
            return RTI_FALSE;
        }
    }

    // Signature
    if (virname) {
        retCode = DDS_DynamicData_set_string(
                    theAVEventInstance,
                    "scan.signature",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    virname);
        if (retCode != DDS_RETCODE_OK) {
            rtiddsscan_err("Failed to set 'signature' property: %d\n", retCode);
            return RTI_FALSE;
        }
    }

    // Message
    if (message) {
        retCode = DDS_DynamicData_set_string(
                    theAVEventInstance,
                    "scan.message",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    message);
        if (retCode != DDS_RETCODE_OK) {
            rtiddsscan_err("Failed to set 'signature' property: %d\n", retCode);
            return RTI_FALSE;
        }
    }

    // Write!
    retCode = DDS_DynamicDataWriter_write(theAVEventWriter, theAVEventInstance, &DDS_HANDLE_NIL);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Malaware writer error: %d\n", retCode);
        return RTI_FALSE;
    }
    return RTI_TRUE;
}

/* }}} */



// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
// Public Functions
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/* {{{ RTIDDSScan_init
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * Initializes the publishing subsystem by creating the participant and the data 
 * writers
 */
int RTIDDSScan_init(int verbose, char *name) {
    char *entityName[2] = {NULL, NULL};

    int ok = 0;
    theVerbose = (verbose > 0);

    if (name == NULL) {
        rtiddsscan_err("Missing data writer name\n");
        goto done;
    }

    if (!_parseDataWriterName(name, entityName)) {
        goto done;
    }

    rtiddsscan_log("Initializing DDS Subsystem (version %s): part='%s', dw='%s'\n", RTIDDSSCAN_VERSION, entityName[0], entityName[1]);
    theDomainParticipant = DDS_DomainParticipantFactory_create_participant_from_config(
            DDS_TheParticipantFactory,
            entityName[0]);
    if (!theDomainParticipant) {
        rtiddsscan_err("Failed to create domain participant '%s\n", entityName[0]);
        rtiddsscan_err("Make sure the provided entity is defined in the USER_QOS_PROFILES.xml\n");
        goto done;
    }

    if (!(theAVEventWriter = _createDatawriter(entityName[1])) ) {
        goto done;
    }

    // Assign user name
    if (getlogin_r(&CLIENTID_USERNAME[0], sizeof(CLIENTID_USERNAME))) {
        rtiddsscan_err("Failed to retrieve running user name: %s (errno=%d)\n", strerror(errno), errno);
        goto done;
    }
    // Retrieve host name
    if (gethostname(&CLIENTID_HOSTNAME[0], sizeof(CLIENTID_HOSTNAME))) {
        rtiddsscan_err("Failed to retrieve host name: %s (errno=%d)\n", strerror(errno), errno);
        goto done;
    }

    sleep(1);
    ok = 1;

done:
    if (ok) {
        rtiddsscan_log("Initialization completed successfully\n");
    } else {
        rtiddsscan_log("Initialization failed\n");
    }
    return ok;
}

/* }}} */
/* {{{ RTIDDSScan_finalize
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_finalize(void) {
    rtiddsscan_log("Finalizing DDSScan...\n");
    if (theDomainParticipant) {
        DDS_DomainParticipant_delete_contained_entities(theDomainParticipant);
    }
    theDomainParticipant = NULL;
    theAVEventWriter = NULL;
    rtiddsscan_log("Successfully finalized DDSScan\n");
}

/* }}} */
/* {{{ RTIDDSScan_start
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_start(void) {
    DDS_ReturnCode_t retCode;

    rtiddsscan_log("Sending LifecycleEvent_Start event...\n");
    if (!_composeOperationEvent(LIFECYCLE_EVENT_START)) {
        return;
    }

    retCode = DDS_DynamicDataWriter_write(theAVEventWriter, theAVEventInstance, &DDS_HANDLE_NIL);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("LifecycleEvent writer error: %d\n", retCode);
    }
}

/* }}} */
/* {{{ RTIDDSScan_done
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_done(const struct RTIDDSScanSummary *scanSummary) {
    DDS_ReturnCode_t retCode;
    char msg[1024];

    _composeOperationEvent(LIFECYCLE_EVENT_COMPLETED);

    // operation.database_version
    retCode = DDS_DynamicData_set_string(
                    theAVEventInstance,
                    "operation.database_version",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    scanSummary->engine_version);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.database_version' property: %d\n", retCode);
        return;
    }

    // operation.database_threat_count
    retCode = DDS_DynamicData_set_ulong(
                    theAVEventInstance,
                    "operation.database_threat_count",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    scanSummary->engine_viruscount);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.database_threat_count' property: %d\n", retCode);
        return;
    }

    // operation.database_last_update
    retCode = DDS_DynamicData_set_ulong(
                    theAVEventInstance,
                    "operation.database_last_update.sec",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    scanSummary->engine_lastupdate);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.database_last_update.sec' property: %d\n", retCode);
        return;
    }
    retCode = DDS_DynamicData_set_ulong(
                    theAVEventInstance,
                    "operation.database_last_update.nanosec",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    0);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.database_last_update.nanosec' property: %d\n", retCode);
        return;
    }

    // operation.message
    snprintf(msg, sizeof(msg),
            "{ \"files_total\": %lu, "
              "\"dirs_total\": %lu, "
              "\"errors_total\": %lu, "
              "\"infected_files\": %lu, "
              "\"run_time\": %lu }",
            scanSummary->res_scanned_files,
            scanSummary->res_scanned_dirs,
            scanSummary->res_errors,
            scanSummary->res_infected_files,
            scanSummary->res_run_time.tv_sec);


    retCode = DDS_DynamicData_set_string(
                    theAVEventInstance,
                    "operation.message",
                    DDS_DYNAMIC_DATA_MEMBER_ID_UNSPECIFIED,
                    msg);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("Failed to set 'operation.message' property: %d\n", retCode);
        return;
    }

    rtiddsscan_log("Done scanning, sending LifecycleEvent_Stop event and Summary...\n");
    retCode = DDS_DynamicDataWriter_write(theAVEventWriter, theAVEventInstance, &DDS_HANDLE_NIL);
    if (retCode != DDS_RETCODE_OK) {
        rtiddsscan_err("LifecycleEvent writer error: %d\n", retCode);
    }
}

/* }}} */
/* {{{ RTIDDSScan_fileScanINFECTED
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_fileScanINFECTED(const char *filename, const char *virname) {
    rtiddsscan_log("Sending FileScan event (IGNORED)...\n");
    _writeFileScanEvent(filename, virname, NULL, FILESCAN_ACTION_IGNORED);
}
/* }}} */
/* {{{ RTIDDSScan_fileScanOK
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_fileScanOK(const char *filename) {
    rtiddsscan_log("Sending FileScan event (ALLOWED)...\n");
    _writeFileScanEvent(filename, NULL, NULL, FILESCAN_ACTION_ALLOWED);
}
/* }}} */
/* {{{ RTIDDSScan_fileScanERROR
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
void RTIDDSScan_fileScanERROR(const char *filename, const char *error) {
    rtiddsscan_log("Sending FileScan event (ERROR)...\n");
    _writeFileScanEvent(filename, NULL, error, FILESCAN_ACTION_ERROR);
}
/* }}} */

