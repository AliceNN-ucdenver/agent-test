# Example Generated Issue

This is an example of what a GitHub issue created by `process-codeql-results.js` looks like.

---

## 🔴 Security Vulnerability: SQL injection

**Detected by**: CodeQL v2.15.3
**Created**: 2025-01-13T14:30:45.123Z

---

### 📋 Vulnerability Details

| Property | Value |
|----------|-------|
| **Severity** | CRITICAL |
| **CodeQL Rule** | `js/sql-injection` |
| **OWASP Category** | [Injection](https://maintainability.ai/docs/prompts/owasp/A03_injection.md) |
| **File** | `examples/owasp/A03_injection/insecure.ts` |
| **Lines** | 15-17 |

### 💻 Vulnerable Code

```typescript
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  const result = await db.query(query);
  return result.rows;
```

**Issue**: This SQL query is built using string concatenation with user input, which may be vulnerable to SQL injection.

**Additional Context**: Use parameterized queries or prepared statements to prevent SQL injection attacks.

---

### 🛡️ Security Context (from MaintainabilityAI)

# A03 - Injection Prevention Prompt

## Role
You are a security-focused software engineer specializing in injection attack prevention and secure data handling.

## Context
Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data can trick the interpreter into executing unintended commands or accessing data without proper authorization.

### Common Injection Types
1. **SQL Injection**: Malicious SQL statements injected into application queries
2. **NoSQL Injection**: Exploitation of NoSQL database queries
3. **OS Command Injection**: Injection of operating system commands
4. **LDAP Injection**: Manipulation of LDAP statements
5. **XPath Injection**: Injection into XML queries
6. **Expression Language (EL) Injection**: Exploitation of expression evaluation

### Attack Vectors
- User input fields (forms, search boxes, URL parameters)
- HTTP headers
- Cookies
- File uploads
- API parameters

### Business Impact
- Unauthorized data access or modification
- Complete database disclosure
- Server compromise
- Data loss or corruption
- Denial of service

## Security Requirements

### 1. Input Validation
- **Allowlist Validation**: Define acceptable input patterns
- **Type Checking**: Enforce expected data types
- **Length Limits**: Restrict input size
- **Character Restrictions**: Block dangerous characters
- **Encoding Validation**: Verify proper encoding

### 2. Parameterized Queries
- **Prepared Statements**: Use placeholders for dynamic values
- **Query Builders**: Use ORM/query builders that auto-escape
- **Separation of Data and Code**: Never concatenate user input into queries
- **Batch Operations**: Use parameterized batch queries

### 3. Context-Specific Encoding
- **SQL Context**: Use database-specific escape functions
- **HTML Context**: HTML entity encoding
- **JavaScript Context**: JavaScript escaping
- **URL Context**: Percent encoding
- **Command Context**: Shell escape functions

### 4. Least Privilege
- **Database Permissions**: Minimal necessary privileges
- **Read-Only Accounts**: For queries that don't need writes
- **Separate Accounts**: Different accounts for different operations
- **No Admin Access**: Never use admin/root accounts in application code

### 5. Error Handling
- **Generic Error Messages**: Don't reveal system details
- **Log Detailed Errors**: Log full errors server-side
- **No Stack Traces**: Never expose stack traces to users
- **Audit Logging**: Log all database operations

## Task

Review the provided code for injection vulnerabilities and implement these controls:

### Step 1: Identify Injection Points
1. Find all locations where user input flows to interpreters
2. Identify the type of injection risk (SQL, NoSQL, Command, etc.)
3. Map data flow from input to execution

### Step 2: Implement Parameterization
```typescript
// ❌ VULNERABLE - String concatenation
const query = `SELECT * FROM users WHERE id = ${userId}`;
const result = await db.query(query);

// ✅ SECURE - Parameterized query
const query = 'SELECT * FROM users WHERE id = $1';
const result = await db.query(query, [userId]);
```

### Step 3: Add Input Validation
```typescript
import { z } from 'zod';

// Define strict validation schema
const userIdSchema = z.string()
  .regex(/^[a-zA-Z0-9-]+$/)
  .min(1)
  .max(36);

// Validate before use
const validatedUserId = userIdSchema.parse(userId);
```

### Step 4: Implement Error Handling
```typescript
try {
  const result = await db.query(query, [validatedUserId]);
  return result.rows;
} catch (error) {
  // Log detailed error server-side
  logger.error('Database query failed', { error, query });

  // Return generic error to client
  throw new Error('Unable to retrieve user data');
}
```

### Step 5: Apply Least Privilege
```typescript
// Use read-only connection for queries
const readOnlyDb = getReadOnlyConnection();
const result = await readOnlyDb.query(query, [validatedUserId]);
```

## Validation Checklist

Before submitting your changes, verify:

### Input Validation
- [ ] All user inputs are validated against strict schemas
- [ ] Allowlist validation is used (not blocklist)
- [ ] Input length limits are enforced
- [ ] Type checking is implemented
- [ ] Special characters are handled appropriately

### Query Safety
- [ ] All queries use parameterized statements
- [ ] No string concatenation with user input
- [ ] ORM/query builder is used correctly
- [ ] Batch operations use parameterization
- [ ] Dynamic query building is avoided

### Security Controls
- [ ] Least privilege database accounts are used
- [ ] Connection strings don't have excessive permissions
- [ ] Error messages are generic for users
- [ ] Detailed errors are logged server-side
- [ ] Context-appropriate encoding is applied

### Testing
- [ ] Unit tests cover injection attack scenarios
- [ ] Tests verify parameterization is working
- [ ] Tests check validation rejects malicious input
- [ ] Integration tests verify end-to-end security
- [ ] Manual testing performed with malicious payloads

### Documentation
- [ ] Comments explain security controls
- [ ] Validation rules are documented
- [ ] Error handling approach is documented
- [ ] Security assumptions are stated

## Examples of Secure Patterns

### SQL Injection Prevention (PostgreSQL)
```typescript
import { z } from 'zod';
import { pool } from './db';

// Validation schema
const loginSchema = z.object({
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_]+$/),
  password: z.string().min(8).max(128)
});

async function authenticateUser(username: string, password: string) {
  // Validate inputs
  const validated = loginSchema.parse({ username, password });

  // Parameterized query
  const query = 'SELECT id, password_hash FROM users WHERE username = $1';

  try {
    const result = await pool.query(query, [validated.username]);

    if (result.rows.length === 0) {
      throw new Error('Invalid credentials');
    }

    const user = result.rows[0];
    const isValid = await bcrypt.compare(validated.password, user.password_hash);

    if (!isValid) {
      throw new Error('Invalid credentials');
    }

    return { id: user.id };
  } catch (error) {
    logger.error('Authentication failed', { error, username: validated.username });
    throw new Error('Authentication failed');
  }
}
```

### NoSQL Injection Prevention (MongoDB)
```typescript
import { z } from 'zod';
import { ObjectId } from 'mongodb';

const userIdSchema = z.string().regex(/^[0-9a-fA-F]{24}$/);

async function getUserById(userId: string) {
  // Validate input
  const validatedId = userIdSchema.parse(userId);

  // Use MongoDB ObjectId (validates and sanitizes)
  const objectId = new ObjectId(validatedId);

  // Query with strict equality (not operators)
  const user = await db.collection('users').findOne({ _id: objectId });

  return user;
}
```

### Command Injection Prevention
```typescript
import { z } from 'zod';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

const filenameSchema = z.string()
  .regex(/^[a-zA-Z0-9_-]+\.(jpg|png|pdf)$/)
  .max(100);

async function processFile(filename: string) {
  // Validate filename
  const validatedFilename = filenameSchema.parse(filename);

  // Use array syntax (no shell interpretation)
  const { spawn } = require('child_process');
  const child = spawn('convert', [
    validatedFilename,
    '-resize', '800x600',
    `output_${validatedFilename}`
  ]);

  return new Promise((resolve, reject) => {
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error('Conversion failed'));
    });
  });
}
```

## Testing Approach

### Unit Tests
```typescript
describe('SQL Injection Prevention', () => {
  it('should reject SQL injection in username', async () => {
    const maliciousUsername = "admin' OR '1'='1";

    await expect(authenticateUser(maliciousUsername, 'password'))
      .rejects.toThrow();
  });

  it('should handle special characters safely', async () => {
    const username = "user'; DROP TABLE users; --";

    await expect(authenticateUser(username, 'password'))
      .rejects.toThrow();
  });

  it('should use parameterized queries', async () => {
    const spy = jest.spyOn(pool, 'query');

    await authenticateUser('validuser', 'validpassword').catch(() => {});

    expect(spy).toHaveBeenCalledWith(
      expect.any(String),
      expect.arrayContaining(['validuser'])
    );
  });
});
```

---

### 📐 Maintainability Considerations

#### COMPLEXITY-REDUCTION

# Complexity Reduction for Maintainable Code

When implementing injection prevention, focus on reducing complexity:

1. **Centralize Validation**: Create reusable validation schemas
2. **Abstract Data Access**: Use repository pattern
3. **Simplify Error Handling**: Consistent error handling across codebase
4. **Use Type Safety**: Leverage TypeScript for compile-time checking

Example:
```typescript
// Centralized validation
export const validators = {
  userId: z.string().regex(/^[a-zA-Z0-9-]+$/).max(36),
  username: z.string().min(3).max(50).regex(/^[a-zA-Z0-9_]+$/),
  email: z.string().email().max(255)
};

// Repository pattern
class UserRepository {
  async findById(id: string) {
    const validated = validators.userId.parse(id);
    return await db.query('SELECT * FROM users WHERE id = $1', [validated]);
  }
}
```

#### DRY-PRINCIPLE

# Don't Repeat Yourself: Security Patterns

Avoid duplicating security logic:

1. **Shared Validation Functions**: Reuse validation schemas
2. **Query Helpers**: Create wrapper functions for common queries
3. **Error Handling Middleware**: Centralize error responses

Example:
```typescript
// Shared query helper
async function executeQuery<T>(
  query: string,
  params: unknown[],
  schema: z.ZodSchema
): Promise<T> {
  const validated = schema.array().parse(params);

  try {
    const result = await pool.query(query, validated);
    return result.rows as T;
  } catch (error) {
    logger.error('Query failed', { error, query });
    throw new Error('Database operation failed');
  }
}
```

---

### 🎯 Threat Model Analysis

#### TAMPERING

# Tampering Threat: SQL Injection

**Threat**: Attacker manipulates SQL queries to modify data

**Attack Scenario**:
```typescript
// Attacker provides: username = "admin'; UPDATE users SET role='admin' WHERE id='123'; --"
const query = `SELECT * FROM users WHERE username = '${username}'`;
```

**Mitigations**:
1. Parameterized queries prevent query manipulation
2. Read-only database connections for read operations
3. Transaction isolation to detect concurrent modifications
4. Audit logging to detect tampering attempts

#### ELEVATION-OF-PRIVILEGE

# Elevation of Privilege: Authentication Bypass

**Threat**: Attacker bypasses authentication via injection

**Attack Scenario**:
```typescript
// Attacker provides: password = "' OR '1'='1"
const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
// Query becomes: SELECT * FROM users WHERE username='admin' AND password='' OR '1'='1'
// Always returns true
```

**Mitigations**:
1. Parameterized queries prevent authentication bypass
2. Password comparison in application code (not SQL)
3. Rate limiting on authentication endpoints
4. Account lockout after failed attempts
5. Multi-factor authentication

---

## 🤖 Claude Remediation Zone

To request a remediation plan, comment:

`@alice Please provide a remediation plan for this vulnerability following the security and maintainability guidelines above.`

### ✅ Human Review Checklist

- [ ] Security fix addresses the root cause
- [ ] Code maintains readability and maintainability
- [ ] Fix doesn't introduce new vulnerabilities
- [ ] Tests are included/updated
- [ ] Documentation is updated
- [ ] Performance impact is acceptable

---

<details>
<summary>📊 Additional Metadata</summary>

- **Detection Time**: 2025-01-13T14:30:45.123Z
- **CodeQL Version**: 2.15.3
- **Repository**: AliceNN-ucdenver/MaintainabilityAI
- **Branch**: main
- **Commit**: abc123def456789
- **Rule ID**: js/sql-injection

</details>

---

## Labels Applied

- `codeql-finding`
- `security/critical`
- `owasp/a03-injection`
- `maintainability/complexity-reduction`
- `maintainability/dry-principle`
- `awaiting-remediation-plan`

## Assignees

(Based on `AUTO_ASSIGN` configuration)

- @security-team
- @alice
- @bob
