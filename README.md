# Remote Operations BOF

This repo serves as an addition to our previously released [SA](https://github.com/trustedsec/CS-Situational-Awareness-BOF) Repo. Our original stance was that we would not release our tooling that modified other systems, and we would only provide information gathering tooling in a ready to go format.

Over time we've seen many other public security companies release their offensive facing tooling, and we now feel it is appropriate for us to release a portion of our offensive tooling.

Nothing in this repo is particularly special, its basic Microsoft Windows operations in BOF form.  These primitives can be used for a large variety of operations.  

## Injection BOF

We've decided to include the injection bof's that we use when doing EDR detection testing.  These BOF's are provided as is and will not be supported (everything under src/Injection and Injection/*)

You are welcome to use these, but issues opened related to these will be closed without review.

## Available Remote Operations commands
|command|notes|
|-------|-----|
|adcs_request| Request an enrollment certificate|
|chromeKey| Decrypts the provided base64 encoded Chrome key |
|enableuser| Enables and unlocks the specified user account |
|procdump|Dumps the specified process to the specified output file|
|ProcessDestroy|Closes handle(s) in a process|
|ProcessListHandles|Lists all open handles in a specified process|
|reg_delete| deletes a registry key|
|reg_save| Save a registry hive to disk|
|reg_set| set / create a registry key|
|sc_config| configure an existing service|
|sc_create| create a new service|
|sc_delete| delete an existing service|
|sc_description| Modify an existing services description|
|sc_start| start an existing service|
|sc_stop| stop an existing service|
|schtaskscreate| Create a new scheduled task (via xml definition)|
|schtasksdelete| Delete an existing scheduled task|
|schtasksstop| stop a running scheduled task|
|setuserpass| Set a users password|
|shspawnas| A misguided attempt at injecting code into a newly spawned process|

Yes schtasksrun is missing, yes that is intentional, but if someone puts in a pull for it I'll accept it on this side.


## Contributing

This repo is intended for single task windows primitives.  That is to say, even if it takes multiple calls, creating a scheduled task is appropriate.

A command that would attempt to pre-generate an implant and perform automated movement using the BOF's in the repo would be awesome, but is not appropriate for submission to this repo directly.

### Code Expectations
* Your code should compile without errors when using the default makefile
* any new BOF defines for resolving functions will be placed in src/common/bofdefs.h
* Code will compile together using the default Makefile (single entry.c file)
* Code will likewise be compatible with the existing toolchain (mingw)
* Code will be written in C. This is to standardize and my personal confidence in validating the code.

### What to expect as a contributor
After your contribution is received, it will receive an in-depth code review and testing.  </br>
After testing is completed, we will have zero or more rounds of change requests based on findings until there are no issues in the code.  At that point it will be accepted into the repository, and your github username will be added to our credit list (if you would prefer not to be added or some other handle to be used, just let me know)