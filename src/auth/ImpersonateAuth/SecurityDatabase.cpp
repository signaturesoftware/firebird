#include "SecurityDatabase.h"


namespace Auth {

	/******************************************************************************
	 *
	 *	Private interface
	 */

	SecurityDatabase::~SecurityDatabase()
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



	/******************************************************************************
	 *
	 *	Public interface
	 */

	void SecurityDatabase::prepare(const char* secureDbName)
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
		dpb.insertString(isc_dpb_config, ParsedList::getNonLoopbackProviders(secureDbName));

		isc_db_handle tempHandle = 0;
		isc_attach_database(status, 0, secureDbName, &tempHandle,
			dpb.getBufferLength(), reinterpret_cast<const char*>(dpb.getBuffer()));
		checkStatus("isc_attach_database", isc_psw_attach);
		lookup_db = tempHandle;

		isc_compile_request(status, &lookup_db, &lookup_req, sizeof(PWD_REQUEST),
			reinterpret_cast<const char*>(PWD_REQUEST));
		if (status[1])
		{
			ISC_STATUS_ARRAY localStatus;
			// ignore status returned in order to keep first error
			isc_detach_database(localStatus, &lookup_db);
		}

		checkStatus("isc_compile_request", isc_psw_attach);
	}

	void SecurityDatabase::checkStatus(const char* callName, ISC_STATUS userError)
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

	bool SecurityDatabase::lookup(void* inMsg, void* outMsg)
	{
		isc_tr_handle lookup_trans = 0;

		isc_start_transaction(status, &lookup_trans, 1, &lookup_db, sizeof(TPB), TPB);
		checkStatus("isc_start_transaction", isc_psw_start_trans);

		isc_start_and_send(status, &lookup_req, &lookup_trans, 0, sizeof(user_name), inMsg, 0);
		checkStatus("isc_start_and_send");

		bool found = false;
		while (true)
		{
			user_record* user = static_cast<user_record*>(outMsg);
			isc_receive(status, &lookup_req, 1, sizeof(user_record), user, 0);
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