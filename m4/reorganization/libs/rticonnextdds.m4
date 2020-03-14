dnl **********************************************************************************
dnl (c) Copyright 2020, Real-Time Innovations, Inc. All rights reserved.
dnl **********************************************************************************
dnl
dnl Check for RTI ConnextDDS
dnl
dnl Requires the following environment variables:
dnl     DEBUG_ENABLED = [0|1] (optional)
dnl
dnl Modifies the following environment variables:
dnl     CC
dnl     LD
dnl     CFLAGS
dnl     LDFLAGS
dnl
dnl Defines the following environment variables:
dnl     NDDSHOME (if not already specified)
dnl     RTICFG_STATIC = "" | "--static"
dnl


dnl **********************************************************************************************
dnl * --with-rticonnextdds
dnl **********************************************************************************************
AC_ARG_WITH(rticonnextdds,
[AC_HELP_STRING([--with-rticonnextdds],[specify the location of RTI Connext DDS (optional)])],
[
        if test "${withval}" = "yes"; then
            AC_MSG_ERROR(missing argument for --with-connextdds parameter);
        else
            NDDSHOME=`realpath "${withval}"`
        fi
],[
        AC_MSG_RESULT(Checking for NDDSHOME...)
        if test "a${NDDSHOME}a" = "aa"; then
            AC_MSG_ERROR(NDDSHOME not defined. You must specify the --with-connextdds argument);
        else
            NDDSSHOME="${NDDSHOME}"
        fi
])

dnl Verify the provided location
AC_CHECK_FILE("${NDDSHOME}/include/ndds/ndds_c.h", 
[
        AC_MSG_RESULT(Found RTI Connext DDS at ${NDDSHOME})
],[
        AC_MSG_ERROR(RTI Connext DDS not found or NDDSHOME not defined)
])

dnl Verify the Connext DDS installation has the connext-config utility
AC_CHECK_FILE("${NDDSHOME}/bin/connext-config", 
[
        AC_MSG_RESULT(Successfully validated connext-config )
],[
   AC_MSG_RESULT()
   AC_MSG_RESULT(Cannot find connext-config utility installed on your RTI Connext DDS home directory)
   AC_MSG_RESULT(For more info see: https://github.com/fabriziobertocci/connext-config)
   AC_MSG_ERROR()
])


dnl **********************************************************************************************
dnl * --with-rticonnextdds-static                                                              *
dnl **********************************************************************************************
RTICFG_STATIC=""
AC_ARG_WITH([rticonnextdds-static],
    [AC_HELP_STRING([--with-rticonnextdds-static],[uses RTI static libraries instead of dynamic libs])],
    [
        RTICFG_STATIC="--static"
        AC_MSG_RESULT(Using RTI ConnextDDS STATIC libraries)
    ], [ 
        AC_MSG_RESULT(Using RTI ConnextDDS DYNAMIC libraries)
    ]
)



dnl **********************************************************************************************
dnl * --with-rticonnextdds-target
dnl **********************************************************************************************
AC_ARG_WITH(rticonnextdds-target,
[AC_HELP_STRING([--with-rticonnextdds-target],[specify the target architecture for RTI Connext DDS (required). Use 'connext-config --list-all' to view the supported targets])],
[
        if test "${withval}" = "yes"; then
            AC_MSG_ERROR(missing argument for --enable-target parameter);
        else
            if test -z `connext-config --list-all | grep ${withval}`; then
                AC_MSG_ERROR(invalid or unsupported target type);
            fi
            if test $? -ne 0; then
                AC_MSG_ERROR(error invoking connext-config, check log for details)
            fi
            AC_MSG_RESULT(Using connext-config to get compiler and linker settings...)
            if test "$DEBUG_ENABLED" = 1; then
                AC_MSG_RESULT(Using RTI ConnextDDS DEBUG libraries)
                RTICFG_DEBUG="--debug"
            else
                AC_MSG_RESULT(Using RTI ConnextDDS RELEASE libraries)
                RTICFG_DEBUG=""
            fi
            # CC="`connext-config --ccomp ${withval}`"
            # LD="`connext-config --clink ${withval}`"
            RTI_CFLAGS="$CFLAGS `connext-config $RTICFG_STATIC $RTICFG_DEBUG --cflags ${withval}`"
            RTI_LDFLAGS="`connext-config $RTICFG_STATIC $RTICFG_DEBUG --ldflags ${withval}`"
            RTI_LIBS="$LDFLAGS `connext-config $RTICFG_STATIC $RTICFG_DEBUG --ldlibs ${withval}`"
        fi
        AC_MSG_RESULT(Building for target ${withval} system)
],[
        AC_MSG_ERROR(you must specify --enable-target with a valid target. See --help for more info)
])

AC_SUBST([RTI_CFLAGS])
AC_SUBST([RTI_LDFLAGS])
AC_SUBST([RTI_LIBS])

