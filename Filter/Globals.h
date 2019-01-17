#ifndef GLOBALS_H_INCLUDED
#define GLOBALS_H_INCLUDED
/*
 * Global defines
 *
 * To port this software to another platform (os / web server), add
 * global defines here and adjust the source, but do not break
 * existing functionality, just add custom defines!
 */

//Which build, exclusive!
#define IISBUILD					//Builds for Windows + IIS (isapi filter)
//#define ISABUILD					//Builds for ISA Server (reverse proxy isapi filter)

//#define EXPERIMENTALBUILD			//include some experimental rules (not fully tested / might produce false positives)
//#define PRIVATEBUILD				//is this a private build (for me only)
//#define TESTBUILD					//for testing purposes only (for me only)

#define STR_HELPER(x) #x
#define STR(x) STR_HELPER(x)

#define APP_NAME			"WebKnight"
#define APP_VERSION			4.6 //also change resources
#define APP_VERSION_STRING	STR(APP_VERSION)

#define APP_SERVER_HEADER	APP_NAME ## "/" ## APP_VERSION_STRING
#define APP_SERVER_URL		"/" ## APP_NAME ## "/"
#define APP_FULLNAME		"AQTRONIX " ## APP_NAME ## " " ## APP_VERSION_STRING
//also adjust the version in the resource file

#endif //GLOBALS_H_INCLUDED