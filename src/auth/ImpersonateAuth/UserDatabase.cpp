

#include "firebird.h"

#include "../jrd/constants.h"
#include "../common/classes/ParsedList.h"
#include "../common/enc_proto.h"
#include "../common/status.h"
#include "../common/classes/init.h"
#include "../common/classes/ClumpletWriter.h"


#include "UserDatabase.h"
#include "UserDbCache.h"

using namespace Firebird;


namespace 
{
	// Added missing BLR codes
	#define blr_declare (unsigned char)3

	const size_t MAX_LEGACY_PASSWORD_LENGTH = 64;			// used to store passwords internally
	static const char* const LEGACY_PASSWORD_SALT = "9z";	// for old ENC_crypt()
	const size_t SALT_LENGTH = 12;					// measured after base64 coding

	// BLR to search database for user name record

	const UCHAR STAFFID_REQUEST[] =
	{
		blr_version5,
				blr_begin,
				   blr_message, 0, 1,0,
					  blr_cstring, 129, 0,
				   blr_message, 1, 4,0,
					  blr_short, 0,
					  blr_varying2, 21,0, 100,0,
					  blr_varying2, 21,0, 20,0,
					  blr_short, 0,
				   blr_receive, 0,
					  blr_begin,
						 blr_declare, 0,0, blr_short, 0,
						 blr_assignment,
							blr_null,
							blr_variable, 0,0,
						 blr_declare, 1,0, blr_varying2, 21,0, 100,0,
						 blr_assignment,
							blr_null,
							blr_variable, 1,0,
						 blr_declare, 2,0, blr_varying2, 21,0, 20,0,
						 blr_assignment,
							blr_null,
							blr_variable, 2,0,
						 blr_stall,
						 blr_label, 0,
							blr_begin,
							   blr_begin,
								  blr_for,
									 blr_singular,
										blr_rse, 1,
										   blr_procedure, 18, 'S','P','_','U','S','E','R','_','L','O','G','I','N','_','L','I','S','T', 0,
											  1,0,
												 blr_parameter, 0, 0, 0,
										   blr_end,
									 blr_begin,
										blr_assignment,
										   blr_field, 0, 7, 'S','T','A','F','F','I','D',
										   blr_variable, 0,0,
										blr_assignment,
										   blr_field, 0, 8, 'U','S','E','R','N','A','M','E',
										   blr_variable, 1,0,
										blr_assignment,
										   blr_field, 0, 5, 'L','O','G','I','N',
										   blr_variable, 2,0,
										blr_end,
								  blr_begin,
									 blr_send, 1,
										blr_begin,
										   blr_assignment,
											  blr_variable, 0,0,
											  blr_parameter, 1, 0, 0,
										   blr_assignment,
											  blr_variable, 1,0,
											  blr_parameter, 1, 1, 0,
										   blr_assignment,
											  blr_variable, 2,0,
											  blr_parameter, 1, 2, 0,
										   blr_assignment,
											  blr_literal, blr_short, 0, 1, 0,
											  blr_parameter, 1, 3, 0,
										   blr_end,
									 blr_stall,
									 blr_end,
								  blr_end,
							   blr_end,
						 blr_end,
				   blr_send, 1,
					  blr_begin,
						 blr_assignment,
							blr_variable, 0,0,
							blr_parameter, 1, 0, 0,
						 blr_assignment,
							blr_variable, 1,0,
							blr_parameter, 1, 1, 0,
						 blr_assignment,
							blr_variable, 2,0,
							blr_parameter, 1, 2, 0,
						 blr_assignment,
							blr_literal, blr_short, 0, 0, 0,
							blr_parameter, 1, 3, 0,
						 blr_end,
				   blr_end,
				blr_eoc
	};

	// Returns data in the following format




	// Transaction parameter buffer

	const UCHAR TPB[4] =
	{
		isc_tpb_version1,
		isc_tpb_read,
		isc_tpb_concurrency,
		isc_tpb_wait
	};

} // anonymous namespace



namespace Auth {

	GlobalPtr<UserDatabases> userDbInstances;

	/******************************************************************************
	 *
	 *	Private interface
	 */

	UserDatabase::~UserDatabase()
	{
		// One can get 'invalid object' errors here cause provider
		// may get unloaded before authentication plugin

		if (lookup_req)
		{
			isc_release_request(status, &lookup_req);
			if (status[1] != isc_bad_req_handle)
				checkStatus("isc_release_request", 0);
		}

		if (lookup_db)
		{
			isc_detach_database(status, &lookup_db);
			if (status[1] != isc_bad_db_handle)
				checkStatus("isc_detach_database", 0);
		}
	}

	bool UserDatabase::test()
	{
		return fb_ping(status, &lookup_db) == FB_SUCCESS;
	}

	void UserDatabase::prepare(const char* userDbName)
	{
		if (lookup_db)
		{
			return;
		}

#ifndef PLUG_MODULE
		fb_shutdown_callback(status, shutdown, fb_shut_preproviders, 0);
#endif

		lookup_db = lookup_req = 0;

		// Perhaps build up a dpb
		ClumpletWriter dpb(ClumpletReader::dpbList, MAX_DPB_SIZE);

		// Attachment is for the security database
		dpb.insertByte(isc_dpb_sec_attach, TRUE);

		// Attach as SYSDBA
		dpb.insertString(isc_dpb_trusted_auth, DBA_USER_NAME, fb_strlen(DBA_USER_NAME));

		// Do not use loopback provider
		dpb.insertString(isc_dpb_config, ParsedList::getNonLoopbackProviders(userDbName));

		isc_db_handle tempHandle = 0;
		isc_attach_database(status, 0, userDbName, &tempHandle,
			dpb.getBufferLength(), reinterpret_cast<const char*>(dpb.getBuffer()));
		checkStatus("isc_attach_database", isc_psw_attach);
		lookup_db = tempHandle;

		isc_compile_request(status, &lookup_db, &lookup_req, sizeof(STAFFID_REQUEST),
			reinterpret_cast<const char*>(STAFFID_REQUEST));
		if (status[1])
		{
			ISC_STATUS_ARRAY localStatus;
			// ignore status returned in order to keep first error
			isc_detach_database(localStatus, &lookup_db);
		}

		checkStatus("isc_compile_request", isc_psw_attach);
	}

	void UserDatabase::checkStatus(const char* callName, ISC_STATUS userError)
	{
		if (status[1] == 0)
			return;

		// suppress throwing errors from destructor which passes userError == 0
		if (!userError)
			return;

		Arg::Gds secDbError(userError);

		string message;
		message.printf("Error in %s() API call when working with legacy security database", callName);
		secDbError << Arg::Gds(isc_random) << message;

		secDbError << Arg::StatusVector(status);
		secDbError.raise();
	}

	bool UserDatabase::lookup(void* inMsg, void* outMsg)
	{
		bool found = false;
		isc_tr_handle lookup_trans = 0;

		isc_start_transaction(status, &lookup_trans, 1, &lookup_db, sizeof(TPB), TPB);
		checkStatus("isc_start_transaction", isc_psw_start_trans);

		isc_start_and_send(status, &lookup_req, &lookup_trans, 0, sizeof(staff_name), inMsg, 0);
		checkStatus("isc_start_and_send");		 
			
		while (true)
		{
			staff_record* user = static_cast<staff_record*>(outMsg);
			isc_receive(status, &lookup_req, 1, sizeof(staff_record), user, 0);
			checkStatus("isc_receive");

			if (!user->flag || status[1])
				break;

			found = true;
		}

		isc_rollback_transaction(status, &lookup_trans);
		checkStatus("isc_rollback_transaction");

		return found;
	}

}