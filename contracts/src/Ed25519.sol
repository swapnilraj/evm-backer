// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import "./Sha512.sol";

/// @title  Ed25519
/// @notice Pure Solidity Ed25519 signature verification library.
/// @dev    Ported from chengwenxi/Ed25519 (Solidity 0.6.8) to ^0.8.24.
///         The original code relied on unchecked overflow in 0.6.x. All
///         intermediate arithmetic uses unchecked blocks or mulmod/addmod.
library Ed25519 {
    uint256 private constant P = 0x7fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffed;
    uint256 private constant L = 0x10000000_00000000_00000000_00000000_14def9de_a2f79cd6_5812631a_5cf5d3ed;
    uint256 private constant D2 = 0x2406d9dc_56dffce7_198e80f2_eef3d130_00e0149a_8283b156_ebd69b94_26b2f159;
    uint256 private constant I_SQRT = 0x2b832480_4fc1df0b_2b4d0099_3dfbd7a7_2f431806_ad2fe478_c4ee1b27_4a0ea0b0;

    struct Point4 {
        uint256 x;
        uint256 u;
        uint256 y;
        uint256 v;
    }

    function _pow22501(uint256 v) private pure returns (uint256 p22501, uint256 p11) {
        p11 = mulmod(v, v, P);
        p22501 = mulmod(p11, p11, P);
        p22501 = mulmod(mulmod(p22501, p22501, P), v, P);
        p11 = mulmod(p22501, p11, P);
        p22501 = mulmod(mulmod(p11, p11, P), p22501, P);
        uint256 a = p22501;
        for (uint256 i = 0; i < 5; i++) { a = mulmod(a, a, P); }
        p22501 = mulmod(p22501, a, P);
        a = p22501;
        for (uint256 i = 0; i < 10; i++) { a = mulmod(a, a, P); }
        a = mulmod(p22501, a, P);
        uint256 b = a;
        for (uint256 i = 0; i < 20; i++) { b = mulmod(b, b, P); }
        a = mulmod(a, b, P);
        for (uint256 i = 0; i < 10; i++) { a = mulmod(a, a, P); }
        p22501 = mulmod(p22501, a, P);
        a = p22501;
        for (uint256 i = 0; i < 50; i++) { a = mulmod(a, a, P); }
        a = mulmod(p22501, a, P);
        b = a;
        for (uint256 i = 0; i < 100; i++) { b = mulmod(b, b, P); }
        a = mulmod(a, b, P);
        for (uint256 i = 0; i < 50; i++) { a = mulmod(a, a, P); }
        p22501 = mulmod(p22501, a, P);
    }

    function _reverse256(uint256 v) private pure returns (uint256) {
        v = ((v & 0xff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff) << 8)
          | ((v & 0xff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00) >> 8);
        v = ((v & 0xffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff) << 16)
          | ((v & 0xffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000) >> 16);
        v = ((v & 0xffffffff_00000000_ffffffff_00000000_ffffffff_00000000_ffffffff) << 32)
          | ((v & 0xffffffff_00000000_ffffffff_00000000_ffffffff_00000000_ffffffff_00000000) >> 32);
        v = ((v & 0xffffffff_ffffffff_00000000_00000000_ffffffff_ffffffff) << 64)
          | ((v & 0xffffffff_ffffffff_00000000_00000000_ffffffff_ffffffff_00000000_00000000) >> 64);
        v = (v << 128) | (v >> 128);
        return v;
    }

    /// @dev Byte-reverse within each 64-bit word of a uint256 (3 swap levels).
    ///      The 64-bit words stay in their original position; only bytes within
    ///      each word are reversed (big-endian → little-endian per word).
    function _swapBytes64(uint256 v) private pure returns (uint256) {
        v = ((v & 0xff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff_00ff00ff) << 8)
          | ((v & 0xff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00_ff00ff00) >> 8);
        v = ((v & 0xffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff_0000ffff) << 16)
          | ((v & 0xffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000_ffff0000) >> 16);
        v = ((v & 0xffffffff_00000000_ffffffff_00000000_ffffffff_00000000_ffffffff) << 32)
          | ((v & 0xffffffff_00000000_ffffffff_00000000_ffffffff_00000000_ffffffff_00000000) >> 32);
        return v;
    }

    function _computeH(bytes32 k, bytes32 r, bytes memory m) private pure returns (uint256) {
        bytes memory rs = new bytes(64 + m.length);
        for (uint256 i = 0; i < 32; i++) { rs[i] = r[i]; }
        for (uint256 i = 0; i < 32; i++) { rs[i + 32] = k[i]; }
        for (uint256 i = 0; i < m.length; i++) { rs[i + 64] = m[i]; }
        uint64[8] memory result = Sha512.hash(rs);
        uint256 h0;
        uint256 h1;
        unchecked {
            h0 = uint256(result[0]) | uint256(result[1]) << 64
               | uint256(result[2]) << 128 | uint256(result[3]) << 192;
            h1 = uint256(result[4]) | uint256(result[5]) << 64
               | uint256(result[6]) << 128 | uint256(result[7]) << 192;
        }
        h0 = _swapBytes64(h0);
        h1 = _swapBytes64(h1);
        return addmod(
            h0,
            mulmod(h1, 0xfffffff_ffffffff_ffffffff_fffffffe_c6ef5bf4_737dcf70_d6ec3174_8d98951d, L),
            L
        );
    }

    function _decompressKey(bytes32 k) private pure returns (uint256 kx, uint256 ky) {
        unchecked {
            uint256 kk = _reverse256(uint256(k));
            ky = kk & 0x7fffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff;
            uint256 ky2 = mulmod(ky, ky, P);
            uint256 u = addmod(ky2, P - 1, P);
            uint256 v = mulmod(ky2, 0x52036cee_2b6ffe73_8cc74079_7779e898_00700a4d_4141d8ab_75eb4dca_135978a3, P) + 1;
            uint256 t = mulmod(u, v, P);
            (kx,) = _pow22501(t);
            kx = mulmod(kx, kx, P);
            kx = mulmod(u, mulmod(mulmod(kx, kx, P), t, P), P);
            t = mulmod(mulmod(kx, kx, P), v, P);
            if (t != u) {
                if (t != P - u) return (0, 0);
                kx = mulmod(kx, I_SQRT, P);
            }
            if ((kx & 1) != kk >> 255) {
                kx = P - kx;
            }
        }
    }

    function _double(Point4 memory pt) private pure {
        unchecked {
            uint256 xx = mulmod(pt.x, pt.v, P);
            uint256 yy = mulmod(pt.y, pt.u, P);
            uint256 zz = mulmod(pt.u, pt.v, P);
            uint256 xx2 = mulmod(xx, xx, P);
            uint256 yy2 = mulmod(yy, yy, P);
            uint256 xxyy = mulmod(xx, yy, P);
            uint256 zz2 = mulmod(zz, zz, P);
            pt.x = xxyy + xxyy;
            pt.u = yy2 - xx2 + P;
            pt.y = xx2 + yy2;
            pt.v = addmod(zz2 + zz2, 2 * P - pt.u, P);
        }
    }

    /// @dev Add from precomputed table. tab0/tab1/tab2 map to table entries.
    ///      For base point (G): tab0=tables[0][0][j], tab1=tables[0][1][j], tab2=tables[0][2][j]
    ///        original code: aa = mulmod(wd, tab1, P); ab = mulmod(ws, tab0, P); ac = mulmod(wt, tab2, P)
    ///      For key point (A): tab0=tables[1][0][j], tab1=tables[1][1][j], tab2=tables[1][2][j]
    ///        original code: aa = mulmod(wd, tab0, P); ab = mulmod(ws, tab1, P); ac = mulmod(wt, tab2, P)
    ///      So the wd/ws multipliers are SWAPPED between G and A tables.
    function _addFromTable(
        Point4 memory pt,
        uint256 tab0, uint256 tab1, uint256 tab2,
        bool negate
    ) private pure {
        unchecked {
            uint256 wx = mulmod(pt.x, pt.v, P);
            uint256 wy = mulmod(pt.y, pt.u, P);
            uint256 wz = mulmod(pt.u, pt.v, P);
            uint256 wt = mulmod(pt.x, pt.y, P);
            uint256 ws = wy + wx;
            uint256 wd = wy - wx + P;
            uint256 aa;
            uint256 ab;
            if (negate) {
                // Key table (A): aa=mulmod(wd,tab0), ab=mulmod(ws,tab1)
                aa = mulmod(wd, tab0, P);
                ab = mulmod(ws, tab1, P);
            } else {
                // Base table (G): aa=mulmod(wd,tab1), ab=mulmod(ws,tab0)
                aa = mulmod(wd, tab1, P);
                ab = mulmod(ws, tab0, P);
            }
            uint256 ac = mulmod(wt, tab2, P);
            pt.x = ab - aa + P;
            pt.y = ab + aa;
            if (negate) {
                pt.u = wz - ac + P;
                pt.v = wz + ac;
            } else {
                pt.u = wz + ac;
                pt.v = wz - ac + P;
            }
        }
    }

    function verify(bytes32 k, bytes32 r, bytes32 s, bytes memory m) internal pure returns (bool) {
        uint256 hh = _computeH(k, r, m);
        (uint256 kx, uint256 ky) = _decompressKey(k);

        uint256 ss;
        unchecked {
            uint256 sv = _reverse256(uint256(s));
            if (sv >= L) return false;
            ss = sv << 3;
        }

        uint256[8][3][2] memory tables;
        _buildKeyTable(tables, kx, ky);

        Point4 memory pt = _scalarMulGMinusHA(tables, ss, hh);
        return _compareR(pt, r);
    }

    function _buildKeyTable(uint256[8][3][2] memory tables, uint256 kx, uint256 ky) private pure {
        unchecked {
        uint256 ks = ky + kx;
        uint256 kd = ky + P - kx;
        uint256 k2dt = mulmod(mulmod(kx, ky, P), D2, P);
        uint256 kky = ky;
        uint256 kkx = kx;
        uint256 kku = 1;
        uint256 kkv = 1;

        for (uint256 dd = 0; dd < 3; dd++) {
            uint256 xx = mulmod(kkx, kkv, P);
            uint256 yy = mulmod(kky, kku, P);
            uint256 zz = mulmod(kku, kkv, P);
            uint256 xx2 = mulmod(xx, xx, P);
            uint256 yy2 = mulmod(yy, yy, P);
            uint256 xxyy = mulmod(xx, yy, P);
            uint256 zz2 = mulmod(zz, zz, P);
            kkx = xxyy + xxyy;
            kku = yy2 - xx2 + P;
            kky = xx2 + yy2;
            kkv = addmod(zz2 + zz2, 2 * P - kku, P);
        }

        uint256 cprod = 1;
        for (uint256 i = 0; i < 8; i++) {
            uint256 cx = mulmod(kkx, kkv, P);
            uint256 cy = mulmod(kky, kku, P);
            uint256 cz = mulmod(kku, kkv, P);
            uint256 ct = mulmod(kkx, kky, P);
            uint256 cs = cy + cx;
            uint256 cd = cy - cx + P;
            uint256 c2z = cz + cz;

            tables[1][0][i] = cs;
            tables[1][1][i] = cd;
            tables[1][2][i] = mulmod(ct, D2, P);
            tables[0][0][i] = c2z;
            tables[0][1][i] = cprod;
            cprod = mulmod(cprod, c2z, P);

            if (i < 7) {
                uint256 ab = mulmod(cs, ks, P);
                uint256 aa = mulmod(cd, kd, P);
                uint256 ac = mulmod(ct, k2dt, P);
                kkx = ab - aa + P;
                kky = ab + aa;
                kku = addmod(c2z, ac, P);
                kkv = addmod(c2z, P - ac, P);
            }
        }

        {
            (uint256 inv, uint256 t) = _pow22501(cprod);
            inv = mulmod(inv, inv, P);
            inv = mulmod(inv, inv, P);
            inv = mulmod(inv, inv, P);
            inv = mulmod(inv, inv, P);
            inv = mulmod(inv, inv, P);
            inv = mulmod(inv, t, P);

            for (uint256 i = 7; ; ) {
                uint256 cinv = mulmod(inv, tables[0][1][i], P);
                tables[1][0][i] = mulmod(tables[1][0][i], cinv, P);
                tables[1][1][i] = mulmod(tables[1][1][i], cinv, P);
                tables[1][2][i] = mulmod(tables[1][2][i], cinv, P);
                if (i == 0) break;
                inv = mulmod(inv, tables[0][0][i], P);
                i--;
            }
        }
        } // end unchecked

        tables[0] = [
            [
                uint256(0x43e7ce9d_19ea5d32_9385a44c_321ea161_67c996e3_7dc6070c_97de49e3_7ac61db9),
                0x40cff344_25d8ec30_a3bb74ba_58cd5854_fa1e3818_6ad0d31e_bc8ae251_ceb2c97e,
                0x459bd270_46e8dd45_aea7008d_b87a5a8f_79067792_53d64523_58951859_9fdfbf4b,
                0x69fdd1e2_8c23cc38_94d0c8ff_90e76f6d_5b6e4c2e_620136d0_4dd83c4a_51581ab9,
                0x54dceb34_13ce5cfa_11196dfc_960b6eda_f4b380c6_d4d23784_19cc0279_ba49c5f3,
                0x4e24184d_d71a3d77_eef3729f_7f8cf7c1_7224cf40_aa7b9548_b9942f3c_5084ceed,
                0x5a0e5aab_20262674_ae117576_1cbf5e88_9b52a55f_d7ac5027_c228cebd_c8d2360a,
                0x26239334_073e9b38_c6285955_6d451c3d_cc8d30e8_4b361174_f488eadd_e2cf17d9
            ],
            [
                uint256(0x227e97c9_4c7c0933_d2e0c21a_3447c504_fe9ccf82_e8a05f59_ce881c82_eba0489f),
                0x226a3e0e_cc4afec6_fd0d2884_13014a9d_bddecf06_c1a2f0bb_702ba77c_613d8209,
                0x34d7efc8_51d45c5e_71efeb0f_235b7946_91de6228_877569b3_a8d52bf0_58b8a4a0,
                0x3c1f5fb3_ca7166fc_e1471c9b_752b6d28_c56301ad_7b65e845_1b2c8c55_26726e12,
                0x6102416c_f02f02ff_5be75275_f55f28db_89b2a9d2_456b860c_e22fc0e5_031f7cc5,
                0x40adf677_f1bfdae0_57f0fd17_9c126179_18ddaa28_91a6530f_b1a4294f_a8665490,
                0x61936f3c_41560904_6187b8ba_a978cbc9_b4789336_3ae5a3cc_7d909f36_35ae7f48,
                0x562a9662_b6ec47f9_e979d473_c02b51e4_42336823_8c58ddb5_2f0e5c6a_180e6410
            ],
            [
                uint256(0x3788bdb4_4f8632d4_2d0dbee5_eea1acc6_136cf411_e655624f_55e48902_c3bd5534),
                0x6190cf2c_2a7b5ad7_69d594a8_2844f23b_4167fa7c_8ac30e51_aa6cfbeb_dcd4b945,
                0x65f77870_96be9204_123a71f3_ac88a87b_e1513217_737d6a1e_2f3a13a4_3d7e3a9a,
                0x23af32d_bfa67975_536479a7_a7ce74a0_2142147f_ac048018_7f1f1334_9cda1f2d,
                0x64fc44b7_fc6841bd_db0ced8b_8b0fe675_9137ef87_ee966512_15fc1dbc_d25c64dc,
                0x1434aa37_48b701d5_b69df3d7_d340c1fe_3f6b9c1e_fc617484_caadb47e_382f4475,
                0x457a6da8_c962ef35_f2b21742_3e5844e9_d2353452_7e8ea429_0d24e3dd_f21720c6,
                0x63b9540c_eb60ccb5_1e4d989d_956e053c_f2511837_efb79089_d2ff4028_4202c53d
            ]
        ];
    }

    function _scalarMulGMinusHA(
        uint256[8][3][2] memory tables,
        uint256 ss,
        uint256 hh
    ) private pure returns (Point4 memory pt) {
        unchecked {
            uint256 hhh = hh + 0x80000000_00000000_00000000_00000000_a6f7cef5_17bce6b2_c09318d2_e7ae9f60;
            pt.x = 0; pt.u = 1; pt.y = 1; pt.v = 1;

            for (uint256 i = 252; ; ) {
                uint256 bit = 8 << i;
                if ((ss & bit) != 0) {
                    uint256 j = (ss >> i) & 7;
                    ss &= ~(7 << i);
                    _addFromTable(pt, tables[0][0][j], tables[0][1][j], tables[0][2][j], false);
                }
                if ((hhh & bit) != 0) {
                    uint256 j = (hhh >> i) & 7;
                    hhh &= ~(7 << i);
                    _addFromTable(pt, tables[1][0][j], tables[1][1][j], tables[1][2][j], true);
                }
                if (i == 0) {
                    uint256 j = hhh & 7;
                    _addFromTable(pt, tables[1][0][j], tables[1][1][j], tables[1][2][j], true);
                    break;
                }
                _double(pt);
                i--;
            }
        }
    }

    function _compareR(Point4 memory pt, bytes32 r) private pure returns (bool) {
        unchecked {
            (uint256 vi, uint256 vj) = _pow22501(mulmod(pt.u, pt.v, P));
            vi = mulmod(vi, vi, P);
            vi = mulmod(vi, vi, P);
            vi = mulmod(vi, vi, P);
            vi = mulmod(vi, vi, P);
            vi = mulmod(vi, vi, P);
            vi = mulmod(vi, vj, P);
            uint256 finalX = mulmod(pt.x, mulmod(vi, pt.v, P), P);
            uint256 finalY = mulmod(pt.y, mulmod(vi, pt.u, P), P);
            bytes32 vr = bytes32(finalY | (finalX << 255));
            vr = bytes32(_reverse256(uint256(vr)));
            return vr == r;
        }
    }
}
