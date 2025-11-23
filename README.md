# EasyHandles
A driver + DLL combo which creates a handle from kernelmode to a target usermode process, bypassing kernel-level handle callbacks.
Allows us to attach popular tools & debuggers such as Cheat Engine to callback-protected processes (EDR, AV, AC, etc). System processes can also be attached to, such as lsass.exe.

## How does it work?

We use the `ObOpenPointerToObject` function in kernelmode to create a handle to a target process; we do this while attaching the kernel driver to the stack of our DLL-injectes process, which bypasses any kernelmode callbacks related to handle opening. 

** Note that processes protected by Process Protection Light (PPL) will still likely fail - other tricks are needed to get past this ** 

A DLL is paired with the driver, which hooks `OpenProcess`. A request is sent to the driver from inside the `OpenProcess` hook to ask the driver for a handle to the target process. So, rather than `OpenProcess` going through the traditional pathway from userland to kernelspace's `ZwOpenProcess` and back, we instead send an IOCTL to our driver, and then return the handle which our driver creates instead by using `ObOpenPointerToObject`.    

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

## Detection & Prevention:

- Since kernelmode callbacks related to handle openings are not triggered, the handle table for all processes must be walked (in the worst case), and the type of handle + target process must be checked (which is the same way you would check for open process handles in usermode). The way this occurs changes whether you're in kernelspace or userland, but both are well-documented.
