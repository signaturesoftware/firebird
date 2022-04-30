

#include "firebird.h"

#include "UserDbCache.h"
#include "UserDatabase.h"
#include "../common/status.h"
#include "../common/isc_proto.h"

#include <string.h>


using namespace Firebird;

namespace Auth {

	void CachedUserDatabase::close()
	{
		FbLocalStatus s;
		TimerInterfacePtr()->start(&s, this, 10 * 1000 * 1000);
		if (s->getState() & IStatus::STATE_ERRORS)
			handler();
	}

	void CachedUserDatabase::handler()
	{
		list->handler(this);
	}


	void UserDatabases::getInstance(IPluginConfig* pluginConfig, CachedUserDatabase::Instance& instance)
	{
		// Determine sec.db name based on existing config
		PathName secDbName;
		{ // config scope
			FbLocalStatus s;
			RefPtr<IFirebirdConf> config(REF_NO_INCR, pluginConfig->getFirebirdConf(&s));
			check(&s);

			static GlobalPtr<ConfigKeys> keys;
			unsigned int secDbKey = keys->getKey(config, "SecurityDatabase");
			const char* tmp = config->asString(secDbKey);
			if (!tmp)
				Arg::Gds(isc_secdb_name).raise();

			secDbName = tmp;
		}

		secDbName.assign("D:\\ICE\\PRINT SOEICE.FDB");

		{ // guard scope
			MutexLockGuard g(arrayMutex, FB_FUNCTION);
			for (unsigned int i = 0; i < dbArray.getCount(); )
			{
				if (secDbName == dbArray[i]->userDbName)
				{
					CachedUserDatabase* fromCache = dbArray[i];
					// if element is just created or test passed we can use it
					if ((!fromCache->userDb) || fromCache->userDb->test())
					{
						instance.set(fromCache);
						break;
					}
					else
					{
						dbArray.remove(i);
						continue;
					}
				}
				++i;
			}

			if (!instance)
			{
				instance.set(FB_NEW CachedUserDatabase(this, secDbName));
				instance->addRef();
				secDbName.copyTo(instance->userDbName, sizeof(instance->userDbName));
				dbArray.add(instance);
			}
		}
	}

	int UserDatabases::shutdown()
	{
		try
		{
			MutexLockGuard g(arrayMutex, FB_FUNCTION);
			for (unsigned int i = 0; i < dbArray.getCount(); ++i)
			{
				if (dbArray[i])
				{
					FbLocalStatus s;
					TimerInterfacePtr()->stop(&s, dbArray[i]);
					check(&s);
					dbArray[i]->release();
					dbArray[i] = NULL;
				}
			}
			dbArray.clear();
		}
		catch (Exception& ex)
		{
			StaticStatusVector st;
			ex.stuffException(st);
			const ISC_STATUS* status = st.begin();
			if (status[0] == 1 && status[1] != isc_att_shutdown)
			{
				iscLogStatus("Legacy security database shutdown", status);
			}

			return FB_FAILURE;
		}

		return FB_SUCCESS;
	}

	void UserDatabases::handler(CachedUserDatabase* tgt)
	{
		try
		{
			MutexLockGuard g(arrayMutex, FB_FUNCTION);

			for (unsigned int i = 0; i < dbArray.getCount(); ++i)
			{
				if (dbArray[i] == tgt)
				{
					dbArray.remove(i);
					tgt->release();
					break;
				}
			}
		}
		catch (Exception& ex)
		{
			StaticStatusVector st;
			ex.stuffException(st);
			const ISC_STATUS* status = st.begin();
			if (status[0] == 1 && status[1] != isc_att_shutdown)
			{
				iscLogStatus("Security database timer handler", status);
			}
		}
	}

} // namespace Auth
