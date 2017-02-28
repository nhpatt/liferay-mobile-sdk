/**
 * Copyright (c) 2000-present Liferay, Inc. All rights reserved.
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

#import "LRBaseService.h"

/**
 * @author Bruno Farache
 */
@interface LRExpandoValueService_v7 : LRBaseService

- (NSDictionary *)getDataWithCompanyId:(long long)companyId className:(NSString *)className tableName:(NSString *)tableName columnNames:(NSArray *)columnNames classPK:(long long)classPK error:(NSError **)error;
- (void)addValuesWithCompanyId:(long long)companyId className:(NSString *)className tableName:(NSString *)tableName classPK:(long long)classPK attributeValues:(NSDictionary *)attributeValues error:(NSError **)error CONVERT_ERROR_TO_THROWS;
- (NSDictionary *)getDataWithCompanyId:(long long)companyId className:(NSString *)className tableName:(NSString *)tableName columnName:(NSString *)columnName classPK:(long long)classPK error:(NSError **)error;
- (NSDictionary *)addValueWithCompanyId:(long long)companyId className:(NSString *)className tableName:(NSString *)tableName columnName:(NSString *)columnName classPK:(long long)classPK data:(NSString *)data error:(NSError **)error;
- (NSDictionary *)getJsonDataWithCompanyId:(long long)companyId className:(NSString *)className tableName:(NSString *)tableName columnName:(NSString *)columnName classPK:(long long)classPK error:(NSError **)error;

@end