import * as dynamodb from "@aws-sdk/client-dynamodb";
import * as ddb from "@aws-sdk/lib-dynamodb";
const docClient = new dynamodb.DynamoDBClient();
const ddbDocClient = ddb.DynamoDBDocumentClient.from(docClient, {
    marshallOptions: {
        removeUndefinedValues: true,
    },
});
import { v4 as uuidv4 } from 'uuid';
const user_pool_id = process.env.user_pool_id;
import { CognitoIdentityProviderClient, AdminCreateUserCommand } from "@aws-sdk/client-cognito-identity-provider";
const region = "us-west-2";
const client = new CognitoIdentityProviderClient({ region });
import { AuthenticationDetails, CognitoUser, CognitoUserPool } from 'amazon-cognito-identity-js';
const userPoolId = process.env.user_pool_id;
const userPoolWebClientId = process.env.cognito_appclient_id;

const check_empty_fields = (event) => {
    let checkEmptyFields = true;
    for (const field in event) {
        if (typeof event[field] == "string") {
            if (event[field].trim().length == 0) {
                checkEmptyFields = false;
            }
        }
    }
    if (checkEmptyFields) {
        return true;
    }
    else {
        return false;
    }
};

export const insert_dynamo = async (params) => {
    try {
        await ddbDocClient.send(new ddb.PutCommand({ ...params, removeUndefinedValues: true }));
        return "SUCCESS";
    }
    catch (err) {
        //console.log(params, err);
        throw new Error(err);
    }
};

export const delete_dynamo = async (params) => {
    try {
        await ddbDocClient.send(new ddb.DeleteCommand({ ...params, removeUndefinedValues: true }));
        return "SUCCESS";
    }
    catch (err) {
        //console.log(params, err);
        throw new Error(err);
    }
};

export const query_dynamo = async (params) => {
    try {
        const results = await ddbDocClient.send(new ddb.QueryCommand(params));
        return results;
    }
    catch (err) {
        //console.log(params);
        console.error(err);
    }
};

export const update_dynamo = async (params) => {
    try {
        const results = await ddbDocClient.send(new ddb.UpdateCommand(params));
        return results;
    }
    catch (err) {
        //console.log(params, err);
        throw new Error(err);
    }
};

export const scan_dynamo = async (params) => {
    try {
        const results = await ddbDocClient.send(new ddb.ScanCommand(params));
        return results;
    }
    catch (err) {
        //console.log(params, err);
        throw new Error(err);
    }
};

export const dynamic_sort = (property) => {
    var sortOrder = 1;
    if (property[0] === '-') {
        sortOrder = -1;
        property = property.substr(1);
    }
    return function(a, b) {
        if (sortOrder == -1) {
            return b[property].localeCompare(a[property]);
        }
        else {
            return a[property].localeCompare(b[property]);
        }
    };
};

const create_cognito_user = async (email_id, poolId) => {
    console.log(email_id, poolId);
    try {
        var params = {
            UserPoolId: poolId,
            Username: email_id.trim().toLowerCase(),
            UserAttributes: [{
                    Name: "email",
                    Value: email_id.trim().toLowerCase(),
                },
                {
                    Name: "email_verified",
                    Value: "true",
                },
            ],
            TemporaryPassword: "Admin@123",
        };
        await client.send(new AdminCreateUserCommand(params));
        return {
            status: "SUCCESS",
            message: "Successfully Created User",
        };
    }
    catch (err) {
        //console.log(params, err);
        throw new Error(err);
    }
};

/*---- USER MANAGEMENT ----*/

const signup_user = async (event) => {
    if (check_empty_fields(event)) {
        let checkUserExistOrNot = {
            TableName: "ipangram_users",
            IndexName: "user_email_id-index",
            KeyConditionExpression: "user_email_id = :user_email_id",
            ExpressionAttributeValues: {
                ":user_email_id": event.user_email_id.toLowerCase()
            },
        };
        let userDetails = await query_dynamo(checkUserExistOrNot);
        if (userDetails.Count == 0) {
            await create_cognito_user(event.user_email_id.toLowerCase(), user_pool_id, false);
            let insertUserDetails = {
                TableName: "ipangram_users",
                Item: {
                    user_id: uuidv4(),
                    user_name: event.user_name,
                    user_email_id: event.user_email_id.toLowerCase(),
                    address: event.address,
                    user_status: "ACTIVE",
                    user_type: event.user_type.toLowerCase(),
                    user_created_on: new Date().getTime(),
                },
            };
            await insert_dynamo(insertUserDetails);
            return { status: "SUCCESS", status_message: "User Signup Successful" };
        }
        else {
            return { status: "SUCCESS", status_message: "User with Email Id Already Present...Please Log In" };
        }
    }
    else {
        throw new Error("Empty Field Occured Cannot Signup!!!");
    }
};

const authenticate_user = async (event) => {
  try {
    const { email, password, newpassword } = event;
    console.log('Email:', email);
    console.log('Password:', password);

    const authenticationData = {
      Username: email,
      Password: password,
    };

    const authenticationDetails = new AuthenticationDetails(authenticationData);
    console.log(userPoolId);
    console.log(userPoolWebClientId);

    const userData = {
      Username: email,
      Pool: new CognitoUserPool({
        UserPoolId: userPoolId,
        ClientId: userPoolWebClientId,
      }),
    };

    const cognitoUser = new CognitoUser(userData);

    const session = await new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session) => resolve(session),
        onFailure: (err) => reject(err),
        newPasswordRequired: (userAttributes, requiredAttributes) => {
          console.log('New password required.');

          if (newpassword) {
            cognitoUser.completeNewPasswordChallenge(newpassword, {}, {
              onSuccess: (newSession) => {
                console.log('New password set successfully:', newSession.getIdToken().getJwtToken());
                resolve(newSession);
              },
              onFailure: (newPasswordErr) => {
                console.error('Setting new password failed:', newPasswordErr);
                reject(newPasswordErr);
              },
            });
          } else {
            console.error('New password is required, but not provided.');
            reject('New password is required, but not provided.');
          }
        },
      });
    });

    console.log('Authentication successful:', session.getIdToken().getJwtToken());
    return true;
  } catch (error) {
    console.error('Authentication failed:', error);
    return false;
  }
};

const login_user = async (event) => {
  try {
    //console.log('Email:', event.email);
    //console.log('Password:', event.password);

    const authenticationData = {
      Username: event.email,
      Password: event.password,
    };

    const authenticationDetails = new AuthenticationDetails(authenticationData);

    const userData = {
      Username: event.email,
      Pool: new CognitoUserPool({
        UserPoolId: userPoolId,
        ClientId: userPoolWebClientId,
      }),
    };

    const cognitoUser = new CognitoUser(userData);

    const session = await new Promise((resolve, reject) => {
      cognitoUser.authenticateUser(authenticationDetails, {
        onSuccess: (session) => resolve(session),
        onFailure: (err) => reject(err),
      });
    });

    console.log('Authentication successful:', session.getIdToken().getJwtToken());
    return true;
  } catch (error) {
    console.error('Authentication failed:', error);
    return false;
  }
};

const get_current_user_details = async (event) => {
    if (check_empty_fields(event)) {
        let getUserDetailsParams = {
            TableName: "ipangram_users",
            IndexName: "user_email_id-index",
            KeyConditionExpression: "user_email_id = :user_email_id",
            ExpressionAttributeValues: {
                ":user_email_id": event.user_email_id.toLowerCase()
            }
        };
        let userDetails = await query_dynamo(getUserDetailsParams);
        console.log("userDetails", userDetails);
        let data = userDetails.Items[0];
        if (userDetails.Count > 0) {
            return { status: "SUCCESS", response: data };
        }
        else {
            throw new Error(`No User Found`);
        }
    }
    else {
        throw new Error("Empty Field Occured!!!");
    }
};

const list_users_through_address = async (event) => {
    let listUserParams = {
        TableName: 'ipangram_users'
    };
    if (event.next_token != null && event.next_token != undefined) {
        listUserParams.ExclusiveStartKey = JSON.parse(Buffer.from(event.next_token.trim(), 'base64').toString('ascii'));
    }
    let users = await scan_dynamo(listUserParams);

    if (users.Count > 0) {
        let response = {};
        users.Items.sort((a, b) => a.address.localeCompare(b.address)); // Sort in ascending order

        response.items = users.Items;
        if (users.LastEvaluatedKey != undefined && users.LastEvaluatedKey != null) {
            response.next_token = Buffer.from(JSON.stringify(users.LastEvaluatedKey)).toString('base64');
        }
        return { status: 'Success', data: response };
    } else {
        throw new Error(`Currently, there are no users to list`);
    }
};

const list_users_through_name = async (event) => {
    let listUserParams = {
        TableName: 'ipangram_users'
    };
    if (event.next_token != null && event.next_token != undefined) {
        listUserParams.ExclusiveStartKey = JSON.parse(Buffer.from(event.next_token.trim(), 'base64').toString('ascii'));
    }
    let users = await scan_dynamo(listUserParams);

    if (users.Count > 0 && event.type == "ascending") {
        let response = {};
        users.Items.sort((a, b) => a.user_name.localeCompare(b.user_name)); // Sort in ascending order

        response.items = users.Items;
        if (users.LastEvaluatedKey != undefined && users.LastEvaluatedKey != null) {
            response.next_token = Buffer.from(JSON.stringify(users.LastEvaluatedKey)).toString('base64');
        }
        return { status: 'Success', data: response };
    }
    else if (users.Count > 0 && event.type == "descending") {
        let response = {};
        users.Items.sort((a, b) => b.user_name.localeCompare(a.user_name)); // Sort in ascending order

        response.items = users.Items;
        if (users.LastEvaluatedKey != undefined && users.LastEvaluatedKey != null) {
            response.next_token = Buffer.from(JSON.stringify(users.LastEvaluatedKey)).toString('base64');
        }
        return { status: 'Success', data: response };
    }

    else {
        throw new Error(`Currently, there are no users to list`);
    }
};

const update_user_details = async (event) => {
    if (check_empty_fields(event)) {
        let checkManagerExistOrNot = {
            TableName: "ipangram_users",
            IndexName: "user_email_id-index",
            KeyConditionExpression: "user_email_id = :user_email_id",
            FilterExpression: "user_type = :user_type",
            ExpressionAttributeValues: {
                ":user_email_id": event.manager_email_id.toLowerCase(),
                ":user_type": "manager"
            },
        };
        let managerDetails = await query_dynamo(checkManagerExistOrNot);
        if (managerDetails.Count > 0) {
            let checkUserExistOrNot = {
                TableName: "ipangram_users",
                IndexName: "user_email_id-index",
                KeyConditionExpression: "user_email_id = :user_email_id",
                ExpressionAttributeValues: {
                    ":user_email_id": event.user_email_id.toLowerCase()
                },
            };
            let userDetails = await query_dynamo(checkUserExistOrNot);
            if (userDetails.Count > 0) {
                let UpdateExpression = "set";
                let ExpressionAttributeNames = {};
                let ExpressionAttributeValues = {};
                for (const field in event) {
                    if (field == "user_name" || field == "address") {
                        UpdateExpression += ` #${field} = :${field} ,`;
                        ExpressionAttributeNames["#" + field] = field;
                        ExpressionAttributeValues[":" + field] = event[field];
                    }
                }
                UpdateExpression = UpdateExpression.slice(0, -1);
                for (let i = 0; i < userDetails.Items.length; i++) {
                    let updateUserDetailsParams = {
                        TableName: "ipangram_users",
                        Key: {
                            user_id: userDetails.Items[i].user_id,
                        },
                        UpdateExpression: UpdateExpression,
                        ExpressionAttributeNames: ExpressionAttributeNames,
                        ExpressionAttributeValues: ExpressionAttributeValues,
                        ReturnValues: "UPDATED_NEW",
                    };
                    await update_dynamo(updateUserDetailsParams);
                }

                return { status: "SUCCESS", status_message: "Updated User Details Successfully" };
            }
            else {
                throw new Error("User Not Found");
            }
        }
        else {
            throw new Error("Manager Not Found");
        }
    }
    else {
        throw new Error("Empty Field Occured!!!");
    }
};

const delete_user_details = async (event) => {
  if (check_empty_fields(event)) {
    let checkManagerExistOrNot = {
      TableName: "ipangram_users",
      IndexName: "user_email_id-index",
      KeyConditionExpression: "user_email_id = :user_email_id",
      FilterExpression: "user_type = :user_type",
      ExpressionAttributeValues: {
        ":user_email_id": event.manager_email_id,
        ":user_type": "manager"
      },
    };
    let managerDetails = await query_dynamo(checkManagerExistOrNot);
    if (managerDetails.Count > 0) {
      let checkUserExistOrNot = {
        TableName: "ipangram_users",
        IndexName: "user_email_id-index",
        KeyConditionExpression: "user_email_id = :user_email_id",
        FilterExpression: "user_type = :user_type",
        ExpressionAttributeValues: {
          ":user_email_id": event.user_email_id.toLowerCase(),
          ":user_type": "member"
        },
      };
      let userDetails = await query_dynamo(checkUserExistOrNot);
      if (userDetails.Count > 0) {
        let deleteUser = {
          TableName: "ipangram_users",
          Key: {
            user_id: userDetails.Items[0].user_id
          }
        };
        await delete_dynamo(deleteUser);
        return { status: "SUCCESS", status_message: "User Deleted Successfully" };
      }
      else {
        throw new Error("Employee with Email Id" + event.user_email_id + "is not present");
      }
    }
    else {
      throw new Error("Manager Not Found");
    }
  }
  else {
    throw new Error("Empty Field Occured!!!");
  }
};

/*----END OF USER MANAGEMENT ----*/

/*---- DEPARTMENT MANAGEMENT ----*/

const create_department = async (event) => {
  if (check_empty_fields(event)) {
    let checkUserExistOrNot = {
      TableName: "ipangram_users",
      IndexName: "user_email_id-index",
      KeyConditionExpression: "user_email_id = :user_email_id",
      FilterExpression: "user_type = :user_type",
      ExpressionAttributeValues: {
        ":user_email_id": event.manager_email_id.toLowerCase(),
        ":user_type": "manager",
      },
    };
    let userDetails = await query_dynamo(checkUserExistOrNot);
    if (userDetails.Count > 0) {
      let checkDepartmentExistOrNot = {
        TableName: "ipangram_department",
        IndexName: "department_name-index",
        KeyConditionExpression: "department_name = :department_name",
        ExpressionAttributeValues: {
          ":department_name": event.department_name.toLowerCase()
        },
      };
      let departmentDetails = await query_dynamo(checkDepartmentExistOrNot);
      if (departmentDetails.Count == 0) {
        let insertUserDetails = {
          TableName: "ipangram_department",
          Item: {
            department_id: uuidv4(),
            department_name: event.department_name.toLowerCase(),
            department_created_by: event.manager_email_id.toLowerCase(),
            department_created_on: new Date().getTime(),
          },
        };
        await insert_dynamo(insertUserDetails);
        return { status: "SUCCESS", status_message: "Department Created Successfully!!!" };
      }
      else {
        return { status: "SUCCESS", status_message: "Department Name is Already Exists" };
      }
    }
    else {
      throw new Error("Only Manager can create department");
    }
  }
  else {
    throw new Error("Empty Field Occured Cannot Signup!!!");
  }
};

const get_department_details = async (event) => {
    if (check_empty_fields(event)) {
        let getUserDetailsParams = {
            TableName: "ipangram_department",
            IndexName: "department_name-index",
            KeyConditionExpression: "department_name = :department_name",
            ExpressionAttributeValues: {
                ":department_name": event.department_name.toLowerCase()
            }
        };
        let departmentDetails = await query_dynamo(getUserDetailsParams);
        let data = departmentDetails.Items[0];
        if (departmentDetails.Count > 0) {
            return { status: "SUCCESS", response: data };
        }
        else {
            throw new Error(`No User Found`);
        }
    }
    else {
        throw new Error("Empty Field Occured!!!");
    }
};

const update_department_details = async (event) => {
    if (check_empty_fields(event)) {
        let checkManagerExistOrNot = {
            TableName: "ipangram_department",
            IndexName: "department_created_by-index",
            KeyConditionExpression: "department_created_by = :department_created_by",
            ExpressionAttributeValues: {
                ":department_created_by": event.manager_email_id
            },
        };
        let managerDetails = await query_dynamo(checkManagerExistOrNot);
        if (managerDetails.Count > 0) {
            let UpdateExpression = "set";
            let ExpressionAttributeNames = {};
            let ExpressionAttributeValues = {};
            for (const field in event) {
                if (field == "department_name") {
                    UpdateExpression += ` #${field} = :${field} ,`;
                    ExpressionAttributeNames["#" + field] = field;
                    ExpressionAttributeValues[":" + field] = event[field];
                }
            }
            UpdateExpression = UpdateExpression.slice(0, -1);
            for (let i = 0; i < managerDetails.Items.length; i++) {
                let updateUserDetailsParams = {
                    TableName: "ipangram_department",
                    Key: {
                        department_id: managerDetails.Items[i].department_id,
                    },
                    UpdateExpression: UpdateExpression,
                    ExpressionAttributeNames: ExpressionAttributeNames,
                    ExpressionAttributeValues: ExpressionAttributeValues,
                    ReturnValues: "UPDATED_NEW",
                };
                console.log(updateUserDetailsParams);
                await update_dynamo(updateUserDetailsParams);
            }

            return { status: "SUCCESS", status_message: "Updated Department Details Successfully" };
        }
        else {
            throw new Error("Manager Not Found");
        }
    }
    else {
        throw new Error("Empty Field Occured!!!");
    }
};

const delete_department_details = async (event) => {
    if (check_empty_fields(event)) {
        let checkManagerExistOrNot = {
            TableName: "ipangram_department",
            IndexName: "department_created_by-index",
            KeyConditionExpression: "department_created_by = :department_created_by",
            ExpressionAttributeValues: {
                ":department_created_by": event.manager_email_id
            },
        };
        let departmentDetails = await query_dynamo(checkManagerExistOrNot);
        if (departmentDetails.Count > 0) {
            let deleteUser = {
                TableName: "ipangram_department",
                Key: {
                    department_id: departmentDetails.Items[0].department_id
                }
            };
            await delete_dynamo(deleteUser);
            return { status: "SUCCESS", status_message: "Department Deleted Successfully" };
        }
        else {
            throw new Error("Employee with Email Id" + event.user_email_id + "is not present");
        }

    }
    else {
        throw new Error("Empty Field Occured!!!");
    }
};

/*----END OF DEPARTMENT MANAGEMENT ----*/

export const handler = async (event) => {
    console.log(JSON.stringify(event));
    switch (event.command) {
        /*--- USER MANAGEMENT ---*/
        case "signupUser":
            return await signup_user(event);
            
        case "loginUser":
            return await login_user(event);
            
        case "authenticateUser":
            return await authenticate_user(event);
                
        case "getCurrentUserDetails":
            return await get_current_user_details(event);
            
        case "listUsersThroughAddress":
            return await list_users_through_address(event);
            
        case "listUsersThroughName":
            return await list_users_through_name(event);
            
        case "updateUserDetails":
            return await update_user_details(event);

        case "deleteUserDetails":
            return await delete_user_details(event);
            
        case "createDepartment":
            return await create_department(event);

        case "getDepartmentDetails":
            return await get_department_details(event);

        case "updateDepartmentDetails":
            return await update_department_details(event);

        case "deleteDepartmentDetails":
            return await delete_department_details(event);

        default:
            throw new Error("Invalid Command");
    }
};