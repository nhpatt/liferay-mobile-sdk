/**
 * Copyright (c) 2000-2013 Liferay, Inc. All rights reserved.
 *
 * This library is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 2.1 of the License, or (at your option)
 * any later version.
 *
 * This library is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 */

#import "OrgLaborService_v62.h"

/**
 * author Bruno Farache
 */
@implementation OrgLaborService_v62

- (NSArray *)getOrgLabors:(long)organizationId {
	NSDictionary *_params = @{
		@"organizationId": @(organizationId)
	};

	NSDictionary *_command = @{@"/orglabor/get-org-labors": _params};

	return (NSArray *)[self.session invoke:_command];
}

- (NSDictionary *)addOrgLabor:(long)organizationId typeId:(int)typeId sunOpen:(int)sunOpen sunClose:(int)sunClose monOpen:(int)monOpen monClose:(int)monClose tueOpen:(int)tueOpen tueClose:(int)tueClose wedOpen:(int)wedOpen wedClose:(int)wedClose thuOpen:(int)thuOpen thuClose:(int)thuClose friOpen:(int)friOpen friClose:(int)friClose satOpen:(int)satOpen satClose:(int)satClose {
	NSDictionary *_params = @{
		@"organizationId": @(organizationId),
		@"typeId": @(typeId),
		@"sunOpen": @(sunOpen),
		@"sunClose": @(sunClose),
		@"monOpen": @(monOpen),
		@"monClose": @(monClose),
		@"tueOpen": @(tueOpen),
		@"tueClose": @(tueClose),
		@"wedOpen": @(wedOpen),
		@"wedClose": @(wedClose),
		@"thuOpen": @(thuOpen),
		@"thuClose": @(thuClose),
		@"friOpen": @(friOpen),
		@"friClose": @(friClose),
		@"satOpen": @(satOpen),
		@"satClose": @(satClose)
	};

	NSDictionary *_command = @{@"/orglabor/add-org-labor": _params};

	return (NSDictionary *)[self.session invoke:_command];
}

- (void)deleteOrgLabor:(long)orgLaborId {
	NSDictionary *_params = @{
		@"orgLaborId": @(orgLaborId)
	};

	NSDictionary *_command = @{@"/orglabor/delete-org-labor": _params};

	[self.session invoke:_command];
}

- (NSDictionary *)updateOrgLabor:(long)orgLaborId typeId:(int)typeId sunOpen:(int)sunOpen sunClose:(int)sunClose monOpen:(int)monOpen monClose:(int)monClose tueOpen:(int)tueOpen tueClose:(int)tueClose wedOpen:(int)wedOpen wedClose:(int)wedClose thuOpen:(int)thuOpen thuClose:(int)thuClose friOpen:(int)friOpen friClose:(int)friClose satOpen:(int)satOpen satClose:(int)satClose {
	NSDictionary *_params = @{
		@"orgLaborId": @(orgLaborId),
		@"typeId": @(typeId),
		@"sunOpen": @(sunOpen),
		@"sunClose": @(sunClose),
		@"monOpen": @(monOpen),
		@"monClose": @(monClose),
		@"tueOpen": @(tueOpen),
		@"tueClose": @(tueClose),
		@"wedOpen": @(wedOpen),
		@"wedClose": @(wedClose),
		@"thuOpen": @(thuOpen),
		@"thuClose": @(thuClose),
		@"friOpen": @(friOpen),
		@"friClose": @(friClose),
		@"satOpen": @(satOpen),
		@"satClose": @(satClose)
	};

	NSDictionary *_command = @{@"/orglabor/update-org-labor": _params};

	return (NSDictionary *)[self.session invoke:_command];
}

- (NSDictionary *)getOrgLabor:(long)orgLaborId {
	NSDictionary *_params = @{
		@"orgLaborId": @(orgLaborId)
	};

	NSDictionary *_command = @{@"/orglabor/get-org-labor": _params};

	return (NSDictionary *)[self.session invoke:_command];
}

@end