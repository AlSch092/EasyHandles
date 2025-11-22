# EasyHandles
Use a driver + DLL to directly insert a handle to a target process in our processes' handle table, bypassing KM callbacks/protections. Allows us to attach popular tools such as Cheat Engine to callback-protected processes (EDR, AV, AC, etc)

## What is this?

We use the `ObOpenPointerToObject` call to directly create a handle to a target process. We do this while attaching the kernel driver to the stack of our process, which bypasses any kernel callbacks. ** Note that processes protected by Process Protection Light (PPL) will still likely fail - other tricks are needed to get past this ** 

A combination of a DLL + driver are used, along with hooking `OpenProcess`. A request is sent to the driver from the `OpenProcess` hook to ask the driver for a handle from our usermode process.  

## How to use

### Driver

- Compile the driver using VS, no special tricks are needed here. Put the compiled .sys into your System32/drivers folder.
- Make sure DSE is turned off (or test mode is turned on), whhich may require disabling Secure Boot
- in `cmd.exe`, run: `sc create EasyHandles type= kernel binPath=C:\Windows\System32\drivers\EasyHandles.sys`
- then, run `sc start EasyHandles` - the driver should now be running. The rest occurs in the DLL from here on.

### DLL
- Compile the DLL
- Inject it into a debugger like Cheat Engine, `OpenProcess` will be hooked inside your debugger
- You can now try to attach Cheat Engine to processes which normally would not allow it, as the driver will get a handle request and the `OpenProcess` hook will return the handle created by the driver. The handle is directly inserted into the handle table of your usermode process/debugger, and no kernelmode callback are triggered.
- If the driver handle creation failed, `OpenProcess` returns `NULL`.

## Example:

Screenshot of attaching Cheat Engine to the `Registry` process, which is normally protected

<img width="1778" height="835" alt="handles" src="https://github.com/user-attachments/assets/9ec157ad-9a69-4203-87e8-b07e9c618ddf" />
