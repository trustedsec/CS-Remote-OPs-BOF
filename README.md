# Remote Operations BOF

This repo serves as an addition to our previously released [SA](https://github.com/trustedsec/CS-Situational-Awareness-BOF) repo. Our original stance was that we would not release our tooling that modified other systems, and we would only provide information gathering tooling in a ready to go format.

Over time, we have seen many other public security companies release their offensive facing tooling, and we now feel it is appropriate for us to release a portion of our offensive tooling.

Nothing in this repo is particularly special, it is basic Microsoft Windows operations in BOF form. These primitives can be used for a large variety of operations.  

## Injection BOF

We have decided to include the injection BOFs that we use when doing EDR detection testing. These BOFs are provided as is and will not be supported (everything under src/Injection and Injection/*)

You are welcome to use these, but issues opened related to these will be closed without review.

## Available Remote Operations commands
|Command|Notes|
|-------|-----|
|adcs_request| Request an enrollment certificate|
|adduser| Add specified user to a machine|
|addusertogroup| Add specified user to a group|
|chromeKey| Decrypt the provided base64 encoded Chrome key|
|enableuser| Enable and unlock the specified user account|
|lastpass | Search Chrome, brave memory for LastPass passwords and data|
|office_tokens| Collect Office JWT Tokens from any Office process|
|procdump| Dump the specified process to the specified output file|
|ProcessDestroy| Close handle(s) in a process|
|ProcessListHandles| List all open handles in a specified process|
|reg_delete| Delete a registry key|
|reg_save| Save a registry hive to disk|
|reg_set| Set / create a registry key|
|sc_config| Configure an existing service|
|sc_create| Create a new service|
|sc_delete| Delete an existing service|
|sc_description| Modify an existing services description|
|sc_start| Start an existing service|
|sc_stop| Stop an existing service|
|schtaskscreate| Create a new scheduled task (via xml definition)|
|schtasksdelete| Delete an existing scheduled task|
|schtasksrun| Start a scheduled task|
|schtasksstop| Stop a running scheduled task|
|setuserpass| Set a user's password|
|shspawnas| A misguided attempt at injecting code into a newly spawned process|
|unexpireuser| Set a user account to never expire|

## Contributing

This repo is intended for single task Windows primitives. That is to say, even if it takes multiple calls, creating a scheduled task is appropriate.

A command that would attempt to pre-generate an implant and perform automated movement using the BOFs in this repo would be awesome. But is not appropriate for submission to this repo directly.

### Code expectations
* Your code should compile without errors when using the default makefile
* Any new BOF defines for resolving functions will be placed in src/common/bofdefs.h
* Code will compile together using the default Makefile (single entry.c file)
* Code will likewise be compatible with the existing toolchain (mingw)
* Code will be written in C. This is to standardize and my personal confidence in validating the code.

### What to expect as a contributor
After a pull request is received, it will receive an in-depth code review and testing.  </br>
After testing is completed, we will have zero or more rounds of change requests based on findings until there are no issues in the code. At that point it will be accepted into the repository, and your GitHub username will be added to our credit list. If you would prefer not to be added or some other handle to be used, just let me know.
