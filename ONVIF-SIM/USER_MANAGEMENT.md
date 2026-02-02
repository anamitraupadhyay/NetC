# ONVIF User Management Implementation

This implementation adds user management functionality to the ONVIF-SIM fake camera simulator.

## Implemented Operations

### 1. CreateUsers (Admin Only)
Creates a new user with the specified username, password, and user level.

**SOAP Request Example:**
```xml
<tds:CreateUsers>
  <tds:User>
    <tds:Username>newuser</tds:Username>
    <tds:Password>newpass</tds:Password>
    <tds:UserLevel>Operator</tds:UserLevel>
  </tds:User>
</tds:CreateUsers>
```

**Access:** Administrator level required

### 2. SetUser (Admin Only)
Updates an existing user's password and/or user level.

**SOAP Request Example:**
```xml
<tds:SetUser>
  <tds:User>
    <tds:Username>existinguser</tds:Username>
    <tds:Password>newpassword</tds:Password>
    <tds:UserLevel>User</tds:UserLevel>
  </tds:User>
</tds:SetUser>
```

**Access:** Administrator level required

### 3. DeleteUsers (Admin Only)
Deletes an existing user from the system.

**SOAP Request Example:**
```xml
<tds:DeleteUsers>
  <tds:Username>usertoremove</tds:Username>
</tds:DeleteUsers>
```

**Access:** Administrator level required

### 4. GetUsers (Authenticated)
Lists all users in the system (already implemented).

**Access:** Any authenticated user

## Authentication Flow

All operations follow a three-way authentication handshake:

1. **No Authentication:** Returns 401 Unauthorized with WWW-Authenticate Digest challenge
2. **Non-Admin User:** Returns 403 Forbidden (for admin-only operations)
3. **Admin User:** Processes the request and returns 200 OK

## User Levels

The system supports five user levels (as per ONVIF spec):
- Administrator
- Operator
- User
- Anonymous
- Extended

## File Structure

### New Files:
- `ONVIF-SIM/fakecamera/authhandler/user_management.h` - User management functions and SOAP templates

### Modified Files:
- `ONVIF-SIM/fakecamera/auth_server.h` - Added request handlers for CreateUsers, SetUser, and DeleteUsers

## Data Persistence

User data is stored in `ONVIF-SIM/fakecamera/authhandler/CredsWithLevel.csv` with the format:
```
username,password,userlevel
admin,pass,Administrator
```

**Note:** The implementation properly preserves passwords when updating or deleting users.

## Implementation Details

### Design Principles
1. **Minimal Changes:** Follows the existing code pattern with else-if structure
2. **No Bloat:** Concise implementation focused on the required functionality
3. **Consistent Style:** Matches existing code conventions
4. **Proper Error Handling:** Returns appropriate HTTP status codes
5. **Password Security:** Passwords are properly preserved during CSV updates

### Key Functions

**In user_management.h:**
- `create_user()` - Creates a new user
- `set_user()` - Updates user information
- `delete_user()` - Removes a user
- `is_admin_user()` - Checks if authenticated user is an admin
- `load_users_with_passwords()` - Loads all users from CSV
- `save_users_to_csv()` - Saves all users to CSV
- `extract_username_from_request()` - Extracts username from SOAP
- `extract_password_from_request()` - Extracts password from SOAP
- `extract_userlevel_from_request()` - Extracts user level from SOAP

## Testing

To build and test:

```bash
cd /home/runner/work/NetC/NetC/ONVIF-SIM/fakecamera
gcc main.c -o onvif_sim -I. -lssl -lcrypto -lpthread
./onvif_sim
```

The server will start on port 8080 (configurable in config.xml).

## Security Considerations

1. All admin operations require Administrator level authentication
2. Authentication uses WS-Security or HTTP Digest protocols
3. Proper validation of user input
4. Password preservation during file operations
5. Error messages don't leak sensitive information

## Compliance

This implementation follows:
- ONVIF Core Specification
- WS-Security standards
- HTTP Digest Authentication (RFC 2617)
- SOAP 1.2 specification
