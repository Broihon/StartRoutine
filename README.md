## StartRoutine

A library with four different methods to execute shellcode in a process. All methods support x86, x64 and wow64 shellcode execution.
All methods will call GetLastError if the to be executed shellcode returns anything other than ERROR_SUCCESS.
The methods will consider the shellcode execution failed if execution time is longer than SR_REMOTE_TIMEOUT (default 2000ms).

---

The following methods can be used:

- NtCreateThreadEx
- Thread hijacking
- SetWindowsHookEx
- QueueUserAPC

---

### NtCreateThreadEx

This method simply spawn a new thread in the specified target process. 
The thread can be cloaked. This option disables DLL_THREAD_ATTACH and DLL_THREAD_DETACH calls to loaded modules, fakes the thread entry point and enables the THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER flag.
Since NtCreateThreadEx ignores session seperation this can be used to execute code in session 0 processes.

### Thread hijacking

This method hijacks a thread by suspending it and redirecting it to shellcode. After the shellcode has been executed normal flow of execution is restored.
This method works cross session.

### SetWindowsHookEx

This methods attempts to execute the shellcode by redirecting the WH_CALLWNDPROC calls of the target process' windows to the shellcode using SetWindowsHookEx.
This method is not cross session compatible.

### QueueUserAPC

This method executes the shellcode by queueing APCs to the target process' threads. Shellcode will prevent the execution from happening more than once.
RtlQueueApcWow64Thread is used when dealing with a wow64.

---

Include "Start Routine.h" and the compiled library or this project, map your shellcode and call StartRoutine or StartRoutine_WOW64 depending on the architecture of the target process.
An indepth description of the StartRoutine(_WOW64) arguments can be found in "Start Routine.h".
"Error.h" contains all possible error values and their respective meanings.