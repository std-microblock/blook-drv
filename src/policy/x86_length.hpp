#pragma once
// x86-64 instruction length decoder.
//
// Hook patches (and the trampoline that replays the overwritten bytes) must not
// end in the middle of an instruction: a trampoline that replays half an
// instruction jumps into nowhere, which showed up as a double fault inside the
// hook handler. This decoder walks the one- and two-byte opcode maps of x86-64
// and returns the length of the instruction at `code`, or 0 when it cannot
// decide - callers treat 0 as "do not hook this function".
// Deliberately includes nothing: every includer already has the kernel (or

namespace blook::x86 {
namespace detail {

inline bool legacy_prefix(unsigned char const byte) {
    switch (byte) {
        case 0x26: case 0x2e: case 0x36: case 0x3e: case 0x64: case 0x65:
        case 0x66: case 0x67: case 0xf0: case 0xf2: case 0xf3:
            return true;
        default:
            return false;
    }
}

// Length of a ModRM byte plus SIB and displacement, starting at `at`.
inline unsigned long long modrm_length(unsigned char const* code, unsigned long long at, unsigned long long available) {
    if (at >= available) return 0;
    unsigned char const modrm = code[at];
    unsigned long long i = at + 1;
    unsigned const mod = modrm >> 6;
    unsigned const rm = modrm & 7;
    if (mod == 3) return i;
    if (rm == 4) {
        if (i >= available) return 0;
        unsigned char const sib = code[i++];
        if (mod == 0 && (sib & 7) == 5) i += 4;
    }
    if (mod == 0 && rm == 5) i += 4;
    else if (mod == 1) i += 1;
    else if (mod == 2) i += 4;
    return i;
}

// Register field of a ModRM byte (used by group opcodes whose immediate only
// exists for some sub-opcodes).
inline unsigned modrm_reg(unsigned char const* code, unsigned long long at, unsigned long long available) {
    if (at >= available) return 8;
    return (code[at] >> 3) & 7;
}

}  // namespace detail

// Returns the length of the instruction at `code` (at most `available` bytes)
// or 0 if it is not decodable here.
inline unsigned long long instruction_length(unsigned char const* code, unsigned long long available) {
    unsigned long long i = 0;
    while (i < available && detail::legacy_prefix(code[i])) ++i;
    if (i < available && (code[i] & 0xf0) == 0x40) ++i;  // REX
    if (i >= available) return 0;
    unsigned char const op = code[i++];

    auto const with_modrm = [&](unsigned long long immediate) -> unsigned long long {
        unsigned long long const m = detail::modrm_length(code, i, available);
        if (!m) return 0;
        return (m + immediate <= available) ? m + immediate : 0;
    };

    switch (op) {
        // One-byte arithmetic/logic with ModRM, no immediate.
        case 0x00: case 0x01: case 0x02: case 0x03:
        case 0x08: case 0x09: case 0x0a: case 0x0b:
        case 0x10: case 0x11: case 0x12: case 0x13:
        case 0x18: case 0x19: case 0x1a: case 0x1b:
        case 0x20: case 0x21: case 0x22: case 0x23:
        case 0x28: case 0x29: case 0x2a: case 0x2b:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x38: case 0x39: case 0x3a: case 0x3b:
        case 0x62: case 0x63:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8a: case 0x8b: case 0x8c: case 0x8d:
        case 0x8e: case 0x8f:
        case 0xd0: case 0xd1: case 0xd2: case 0xd3:
        case 0xd8: case 0xd9: case 0xda: case 0xdb:
        case 0xdc: case 0xdd: case 0xde: case 0xdf:
        case 0xfe: case 0xff:
            return with_modrm(0);
        // With an 8-bit immediate.
        case 0x6b: case 0x80: case 0x83: case 0xc0: case 0xc1:
            return with_modrm(1);
        // With a 32-bit immediate.
        case 0x69: case 0x81: case 0xc7:
            return with_modrm(4);
        case 0xc6:
            return with_modrm(1);
        // Group 3: the immediate only exists for /0 (test) and /1.
        case 0xf6:
            return with_modrm(detail::modrm_reg(code, i, available) <= 1 ? 1 : 0);
        case 0xf7:
            return with_modrm(detail::modrm_reg(code, i, available) <= 1 ? 4 : 0);
        // Mov r8, imm8 / mov r, imm(16/32/64).
        case 0xb0: case 0xb1: case 0xb2: case 0xb3:
        case 0xb4: case 0xb5: case 0xb6: case 0xb7:
            return i + 1 <= available ? i + 1 : 0;
        case 0xb8: case 0xb9: case 0xba: case 0xbb:
        case 0xbc: case 0xbd: case 0xbe: case 0xbf: {
            // REX.W was consumed above; remember it from the byte before i-1.
            bool const wide = (i >= 2) && ((code[i - 2] & 0xf0) == 0x40) &&
                              ((code[i - 2] & 8) != 0);
            unsigned long long const size = wide ? 8 : 4;
            return i + size <= available ? i + size : 0;
        }
        // Shifts/rotates with imm8 (already handled 0xc0/0xc1 above).
        case 0xa8: case 0xa9: {
            unsigned long long const size = (op == 0xa8) ? 1 : 4;
            return i + size <= available ? i + size : 0;
        }
        // Push/pop/xchg and friends: single byte.
        case 0x06: case 0x07: case 0x0e: case 0x16: case 0x17: case 0x1e: case 0x1f:
        case 0x27: case 0x2f: case 0x37: case 0x3f:
        case 0x50: case 0x51: case 0x52: case 0x53: case 0x54: case 0x55:
        case 0x56: case 0x57: case 0x58: case 0x59: case 0x5a: case 0x5b:
        case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x90: case 0x91: case 0x92: case 0x93: case 0x94: case 0x95:
        case 0x96: case 0x97: case 0x98: case 0x99: case 0x9b: case 0x9c:
        case 0x9d: case 0x9e: case 0x9f:
        case 0xa4: case 0xa5: case 0xa6: case 0xa7: case 0xaa: case 0xab:
        case 0xac: case 0xad: case 0xae: case 0xaf:
        case 0xc3: case 0xc9: case 0xcb: case 0xcc: case 0xce: case 0xcf:
        case 0xec: case 0xed: case 0xee: case 0xef:
        case 0xf1: case 0xf4: case 0xf5: case 0xf8: case 0xf9: case 0xfa:
        case 0xfb: case 0xfc: case 0xfd:
            return i;
        // Short branches and pushes with imm8.
        case 0x6a: case 0x70: case 0x71: case 0x72: case 0x73: case 0x74:
        case 0x75: case 0x76: case 0x77: case 0x78: case 0x79: case 0x7a:
        case 0x7b: case 0x7c: case 0x7d: case 0x7e: case 0x7f:
        case 0xcd: case 0xe0: case 0xe1: case 0xe2: case 0xe3: case 0xe4:
        case 0xe5: case 0xe6: case 0xe7: case 0xeb:
            return i + 1 <= available ? i + 1 : 0;
        // Mov with an absolute 64-bit offset.
        case 0xa0: case 0xa1: case 0xa2: case 0xa3:
            return i + 8 <= available ? i + 8 : 0;
        // Near branches and 32-bit immediates.
        case 0x68: case 0xe8: case 0xe9:
            return i + 4 <= available ? i + 4 : 0;
        case 0xca:
            return i + 2 <= available ? i + 2 : 0;
        case 0xc8:
            return i + 3 <= available ? i + 3 : 0;
        case 0xc2:
            return i + 2 <= available ? i + 2 : 0;
        case 0x0f: {
            if (i >= available) return 0;
            unsigned char const op2 = code[i++];
            switch (op2) {
                // Two-byte opcodes with no ModRM and no immediate.
                case 0x05: case 0x06: case 0x07: case 0x08: case 0x09:
                case 0x0b: case 0x0e:
                case 0x30: case 0x31: case 0x32: case 0x33: case 0x34:
                case 0x35: case 0x36: case 0x37:
                case 0x77:
                case 0xa0: case 0xa1: case 0xa2: case 0xa8: case 0xa9:
                case 0xaa:
                    return i;
                // jcc rel32
                case 0x80: case 0x81: case 0x82: case 0x83: case 0x84:
                case 0x85: case 0x86: case 0x87: case 0x88: case 0x89:
                case 0x8a: case 0x8b: case 0x8c: case 0x8d: case 0x8e:
                case 0x8f:
                    return i + 4 <= available ? i + 4 : 0;
                case 0xba:
                    return detail::modrm_length(code, i, available)
                               ? (i + (detail::modrm_length(code, i, available) - i) + 1 <= available
                                      ? detail::modrm_length(code, i, available) + 1
                                      : 0)
                               : 0;
                // Three-byte maps are not needed for prologues; refuse them.
                case 0x38: case 0x3a:
                    return 0;
                default: {
                    unsigned long long const m = detail::modrm_length(code, i, available);
                    return m;  // SSE/integer forms with ModRM and no immediate
                }
            }
        }
        default:
            return 0;
    }
}

}  // namespace blook::x86
