Linux Runtime Process Manipulation
==
* [Linux x86 run-time process manipulation](http://www.hick.org/code/skape/papers/needle.txt) by skape
* [Runtime Process Infection](http://www.phrack.org/issues.html?issue=59&id=8&mode=txt) by anonymous
* [Chapter 8. Behind the process](http://www.bottomupcs.com/elf.html)
* [System V ABI Documentation](http://www.sco.com/developers/gabi/latest/contents.html)

Calling Conventions
==
<table>
	<tr><td>Type</td><td>Stack Cleanup</td><td>Parameters</td></tr>
	<tr><td>cdecl</td><td>caller</td><td>on stack in reverse order (right to left)</td></tr>
	<tr><td>stdcall</td><td>callee</td><td>on stack in reverse order (right to left)</td></tr>
	<tr><td>fastcall</td><td>callee</td><td>in registers (ECX, EDX) then on stack in reverse order (right to left)</td></tr>
	<tr><td>thiscall</td><td>callee</td><td>on stack; this pointer in ECX</td></tr>
	<tr><td>Microsoft x64</td><td>caller</td><td>in registers (RCX, RDX, R8, R9) then on stack in reverse order (right to left)</td><tr>
	<tr><td>System V AMD64 ABI</td><td>caller</td><td>in registers (RDI, RSI, RDX, RCX, R8, R9) then on stack in reverse order (right to left)</td></tr>
</table>
