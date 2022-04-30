#pragma once

#include "firebird.h"

#include "ibase.h"

#include "UserDbCache.h"


using namespace Firebird;


namespace {

	typedef char staff_name[129];

	/*struct staff_name
	{
		TEXT name[100];
		SHORT name_length;
	};*/

	//typedef char staff_record[110];

	struct staff_record
	{
		SSHORT staffId;
		SSHORT u_len;
		TEXT username[100];
		SSHORT l_len;
		TEXT login[20];
		SSHORT flag;
	};
}
  
 

namespace Auth {

	extern GlobalPtr<UserDatabases> userDbInstances;

	class UserDatabase : public VUserDb
	{
	public:
		bool lookup(void* inMsg, void* outMsg) override;
		bool test() override; 

		// This 2 are needed to satisfy temporarily different calling requirements
		static int shutdown(const int, const int, void*)
		{
			return userDbInstances->shutdown();
		}
		static void cleanup()
		{
			userDbInstances->shutdown();
		}

		UserDatabase(const char* userDbName)
			: lookup_db(0), lookup_req(0)
		{
			prepare(userDbName);
		}

	private:
		ISC_STATUS_ARRAY status;

		isc_db_handle lookup_db;
		isc_req_handle lookup_req;

		~UserDatabase();

		void prepare(const char* userDbName);
		void checkStatus(const char* callName, ISC_STATUS userError = isc_psw_db_error);
	};

}