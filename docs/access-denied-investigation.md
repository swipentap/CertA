# Investigation: MSB3021 Access denied when building CertA.UITests

## What was observed

**Failed run** (from Cursor with `required_permissions: ["all"]`):

- Restore: succeeded; packages path = `/Users/shadowchamber/.nuget/packages/`
- Build: failed during Copy step
- Error: `MSB3021: Unable to copy file "<source>" to "bin/Release/net9.0/<file>". Access to the path '/Users/shadowchamber/Projects/CertA/CertA.UITests/bin/Release/net9.0/<file>' is denied.`
- Source path: `/Users/shadowchamber/.nuget/packages/...`
- Destination path: `/Users/shadowchamber/Projects/CertA/CertA.UITests/bin/Release/net9.0/...`
- Emitted from: `Microsoft.Common.CurrentVersion.targets (5035,5)` (Copy task)

**Successful run** (from Cursor, default sandbox):

- Restore: used `RestorePackagesPath=/var/folders/.../cursor-sandbox-cache/.../nuget`
- Build: succeeded; Copy from that cache to `bin/Release/net9.0/` completed with no errors

## Checks performed

1. **Destination directory** `CertA.UITests/bin/Release/net9.0/`:
   - Exists; owner `shadowchamber`, group `staff`
   - Mode `drwxr-xr-x` (no ACLs; `ls -le` shows no ACL column)
   - Extended attributes: only `com.apple.provenance`
   - File flags: none (`ls -lO` shows `-`)

2. **Reproduction**: Running `dotnet build CertA.UITests -c Release -v diag` from the project root did **not** reproduce the failure; build completed successfully. That run used the sandbox NuGet path.

3. **MSB3021**: Occurs when the MSBuild Copy task fails. The message "Access to the path '...' is denied" is the standard .NET `UnauthorizedAccessException.Message`. The task does not log the underlying HResult or errno, so the exact OS-level reason is not in the log.

4. **Process list**: Attempt to list processes that might hold the destination files (`pgrep -fl dotnet`) failed in this environment (sysmond/service not found). So it was not possible to verify here whether a process had the files open.

## Verified difference between the two runs

| Aspect        | Failed run                    | Successful run                          |
|---------------|--------------------------------|-----------------------------------------|
| NuGet packages path | `/Users/shadowchamber/.nuget/packages/` | `/var/folders/.../cursor-sandbox-cache/.../nuget` |
| Write to `bin/Release/net9.0/` | Denied                         | Succeeded                               |

## What is not proven

- Whether the denial was due to a file lock, permissions, read-only state, or something else.
- Whether a specific process (e.g. testhost, IDE) had the destination files open during the failed run.

## How to get the exact cause on your machine

1. **Capture the real error**: When the failure happens again, run the build under a tracer so the failing syscall and errno are visible, e.g.  
   `dtruss -f -e -t open,openat,write dotnet build CertA.UITests/CertA.UITests.csproj -c Release`  
   and look for the call that returns EACCES/EPERM/EBUSY on the destination path.

2. **Check for file locks**: When the error occurs, run  
   `lsof +D /Users/shadowchamber/Projects/CertA/CertA.UITests/bin/Release/net9.0`  
   to see which process has which file open.

3. **Optional**: Build with a custom task or wrapper that catches the exception in the Copy path and logs `exception.ToString()` (including inner exception and HResult) so the exact failure reason is recorded.
