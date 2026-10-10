# Third-party notices

## libev 4.33

FTUN vendors the complete libev 4.33 release from the upstream distribution
archive. The archive SHA-256 is
`507eb7b8d1015fbec5b935f34ebed15bf346bed04a11ab82b8eee848c4205aea`.
Its upstream signify signature was verified with key ID `940438b32e6fc629`.

libev is available under the two-clause BSD license or, alternatively, the
GNU General Public License version 2 or later. FTUN uses the two-clause BSD
terms. The complete upstream notice is retained in
`third_party/libev/LICENSE`.

## cJSON 1.7.19

FTUN vendors the unmodified cJSON parser source and header from the upstream
v1.7.19 release at commit `c859b25da02955fef659d658b8f324b5cde87be3`.
The GitHub release archive SHA-256 is
`7fa616e3046edfa7a28a32d5f9eacfd23f92900fe1f8ccd988c1662f30454562`.

cJSON is distributed under the MIT license. The complete upstream notice is
retained in `third_party/cjson/LICENSE`.

## heiher/lwIP

FTUN vendors the complete heiher/lwIP source tree at commit
`150d2b1a2658612741b4ac002578d440e7874540`. The GitHub commit archive
SHA-256 is
`bab562a52da5ccad9e66ec3af98e559249c0da2cb21ef68a399bc91cae31a416`.

FTUN carries one narrow portability patch that replaces direct access to the
dual-stack-only `ip_addr_t.type` field with lwIP's `IP_GET_TYPE` macro. This
preserves the fork's pretend-UDP behavior while allowing the reviewed IPv4-only
configuration to compile. The patch is retained under
`third_party/lwip/patches` and is checked together with the complete source tree.

lwIP is distributed under the three-clause BSD license. The complete upstream
notice is retained in `third_party/lwip/LICENSE`.
