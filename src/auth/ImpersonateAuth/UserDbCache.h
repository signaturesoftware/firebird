
#ifndef FB_USERDBCACHE_H
#define FB_USERDBCACHE_H

#include "firebird/Interface.h"
#include "../common/classes/ImplementHelper.h"
#include "../common/classes/fb_string.h"
#include "../common/classes/array.h"
#include "../common/classes/alloc.h"
#include "../common/classes/auto.h"


namespace Auth {

	class VUserDb
	{
	public:
		VUserDb()
		{
		}

		virtual ~VUserDb()
		{
		}

		virtual bool lookup(void* inMsg, void* outMsg) = 0;
		virtual bool test() = 0;
	};


	class UserDatabases;

	class CachedUserDatabase FB_FINAL
		: public Firebird::RefCntIface<Firebird::ITimerImpl<CachedUserDatabase, Firebird::CheckStatusWrapper> >
	{
	public:
		char userDbName[MAXPATHLEN + 1];

		CachedUserDatabase(UserDatabases* l, const Firebird::PathName& nm)
			: userDb(nullptr), list(l)
		{
			nm.copyTo(userDbName, sizeof userDbName);
		}

		// ITimer implementation
		void handler();
		void close();

		Firebird::Mutex mutex;
		Firebird::AutoPtr<VUserDb> userDb;
		UserDatabases* list;

	public:
		// Related RAII holder
		class Instance : public Firebird::RefPtr<CachedUserDatabase>
		{
		public:
			Instance()
			{ }

			void set(CachedUserDatabase* db)
			{
				fb_assert(!hasData());
				fb_assert(db);

				assign(db);
				(*this)->mutex.enter(FB_FUNCTION);
			}

			void reset()
			{
				if (hasData())
				{
					(*this)->mutex.leave();
					(*this)->close();
					assign(nullptr);
				}
			}

			~Instance()
			{
				if (hasData())
				{
					(*this)->mutex.leave();
					(*this)->close();
				}
			}
		};
	};

	class UserDatabases
	{
	public:
		UserDatabases(MemoryPool& p)
			: dbArray(p)
		{ }

	private:
		Firebird::HalfStaticArray<CachedUserDatabase*, 4> dbArray;
		Firebird::Mutex arrayMutex;

	public:
		void getInstance(Firebird::PathName secDbName, CachedUserDatabase::Instance& instance);
		int shutdown();
		void handler(CachedUserDatabase* tgt);
	};

} // namespace Auth

#endif // FB_USERDBCACHE_H
