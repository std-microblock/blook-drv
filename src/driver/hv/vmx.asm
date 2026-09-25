; Adapted from jonomango/hv (MIT). See LICENSES/jonomango-hv.txt and docs/REFERENCES.md.
.code
public blook_vmcall_site

?vmx_invept@hv@@YAXW4invept_type@@AEBUinvept_descriptor@@@Z proc
  ; The type is a 32-bit enum parameter, so only the low half of RCX is
  ; defined on entry. INVEPT takes the type in 32 bits and requires bits
  ; 63:32 of RCX to be zero: with garbage in the upper half the invalidation
  ; fails silently (it only sets the VM-instruction-error) and the guest
  ; keeps using a stale translation of a page whose view just changed.
  mov ecx, ecx
  invept rcx, oword ptr [rdx]
  ret
?vmx_invept@hv@@YAXW4invept_type@@AEBUinvept_descriptor@@@Z endp

?vmx_invvpid@hv@@YAXW4invvpid_type@@AEBUinvvpid_descriptor@@@Z proc
  ; Same zero-extension as vmx_invept: the type must occupy a clean low half.
  mov ecx, ecx
  invvpid rcx, oword ptr [rdx]
  ret
?vmx_invvpid@hv@@YAXW4invvpid_type@@AEBUinvvpid_descriptor@@@Z endp

?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z proc
  ; move input into registers
  mov rax, [rcx]       ; code
  mov rdx, [rcx + 10h] ; args[1]
  mov r8,  [rcx + 18h] ; args[2]
  mov r9,  [rcx + 20h] ; args[3]
  mov r10, [rcx + 28h] ; args[4]
  mov r11, [rcx + 30h] ; args[5]
  mov rcx, [rcx + 08h] ; args[0]

blook_vmcall_site::
  vmcall

  ret
?vmx_vmcall@hv@@YA_KAEAUhypercall_input@1@@Z endp

end
