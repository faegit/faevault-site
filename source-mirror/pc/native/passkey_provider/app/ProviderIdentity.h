#pragma once
#include <windows.h>

// Stable production identity. Never change these values during an ordinary upgrade.
inline constexpr GUID vault_plugin_guid // 443e631d-c94b-4d9c-b43e-daa99a0311d8
{
    0x443e631d, 0xc94b, 0x4d9c, { 0xb4, 0x3e, 0xda, 0xa9, 0x9a, 0x03, 0x11, 0xd8 }
};
inline constexpr char vault_plugin_aaguid_string[] = "22d9be39-8865-42e3-a143-dda6ae9796af";
inline constexpr BYTE vault_plugin_aaguid_bytes[] = {
    0x22, 0xd9, 0xbe, 0x39, 0x88, 0x65, 0x42, 0xe3,
    0xa1, 0x43, 0xdd, 0xa6, 0xae, 0x97, 0x96, 0xaf
};
inline constexpr GUID contosoplugin_guid = vault_plugin_guid; // compatibility alias for imported sample files
