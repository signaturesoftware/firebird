/*
 *  The contents of this file are subject to the Initial
 *  Developer's Public License Version 1.0 (the "License");
 *  you may not use this file except in compliance with the
 *  License. You may obtain a copy of the License at
 *  http://www.ibphoenix.com/main.nfs?a=ibphoenix&page=ibp_idpl.
 *
 *  Software distributed under the License is distributed AS IS,
 *  WITHOUT WARRANTY OF ANY KIND, either express or implied.
 *  See the License for the specific language governing rights
 *  and limitations under the License.
 *
 *  The Original Code was created by Dmitry Yemanov
 *  for the Firebird Open Source RDBMS project.
 *
 *  Copyright (c) 2009 Dmitry Yemanov <dimitr@firebirdsql.org>
 *  and all contributors signed below.
 *
 *  All Rights Reserved.
 *  Contributor(s): ______________________________________.
 */

#include "firebird.h"
#include "../jrd/jrd.h"
#include "../jrd/req.h"
#include "../jrd/cmp_proto.h"
#include "../jrd/met_proto.h"
#include "../jrd/vio_proto.h"

#include "RecordSource.h"

using namespace Firebird;
using namespace Jrd;

// -------------------------------
// Data access: virtual table scan
// -------------------------------

VirtualTableScan::VirtualTableScan(CompilerScratch* csb, const string& alias,
								   StreamType stream, jrd_rel* relation)
	: RecordStream(csb, stream), m_relation(relation), m_alias(csb->csb_pool, alias)
{
	m_impure = csb->allocImpure<Impure>();
	m_cardinality = csb->csb_rpt[stream].csb_cardinality;
}

void VirtualTableScan::open(thread_db* tdbb) const
{
	Request* const request = tdbb->getRequest();
	Impure* const impure = request->getImpure<Impure>(m_impure);

	impure->irsb_flags = irsb_open;

	record_param* const rpb = &request->req_rpb[m_stream];
	rpb->getWindow(tdbb).win_flags = 0;

	VIO_record(tdbb, rpb, getFormat(tdbb, m_relation), request->req_pool);

	rpb->rpb_number.setValue(BOF_NUMBER);
}

void VirtualTableScan::close(thread_db* tdbb) const
{
	Request* const request = tdbb->getRequest();

	invalidateRecords(request);

	Impure* const impure = request->getImpure<Impure>(m_impure);

	if (impure->irsb_flags & irsb_open)
		impure->irsb_flags &= ~irsb_open;
}

bool VirtualTableScan::getRecord(thread_db* tdbb) const
{
	JRD_reschedule(tdbb);

	Request* const request = tdbb->getRequest();
	record_param* const rpb = &request->req_rpb[m_stream];
	Impure* const impure = request->getImpure<Impure>(m_impure);

	if (!(impure->irsb_flags & irsb_open))
	{
		rpb->rpb_number.setValid(false);
		return false;
	}

	rpb->rpb_runtime_flags &= ~RPB_CLEAR_FLAGS;

	rpb->rpb_number.increment();

	if (retrieveRecord(tdbb, m_relation, rpb->rpb_number.getValue(), rpb->rpb_record))
	{
		rpb->rpb_number.setValid(true);
		return true;
	}

	rpb->rpb_number.setValid(false);
	return false;
}

bool VirtualTableScan::refetchRecord(thread_db* /*tdbb*/) const
{
	return true;
}

bool VirtualTableScan::lockRecord(thread_db* /*tdbb*/) const
{
	status_exception::raise(Arg::Gds(isc_record_lock_not_supp));
	return false; // compiler silencer
}

void VirtualTableScan::print(thread_db* tdbb, string& plan, bool detailed, unsigned level) const
{
	if (detailed)
	{
		plan += printIndent(++level) + "Table " +
			printName(tdbb, m_relation->rel_name.c_str(), m_alias) + " Full Scan";
		printOptInfo(plan);
	}
	else
	{
		if (!level)
			plan += "(";

		plan += printName(tdbb, m_alias, false) + " NATURAL";

		if (!level)
			plan += ")";
	}
}
