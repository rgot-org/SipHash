<?php

namespace rgot;

class SipHash {

    const VERSION = '0.0.1';
    const UINT8_MASK = 0xFF;
    private static $m_idx , $msg_byte_counter, $m, $v0, $v1, $v2, $v3 ;

    public static function hash_2_4($key, $str) {
        $key = str_pad($key, 16, "\x0", STR_PAD_RIGHT);
        $k = unpack('C16', $key);
        self::$v0 = [0x73, 0x6f, 0x6d, 0x65, 0x70, 0x73, 0x65, 0x75];
        self::$v1 = [0x64, 0x6f, 0x72, 0x61, 0x6e, 0x64, 0x6f, 0x6d];
        self::$v2 = [0x6c, 0x79, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x61];
        self::$v3 = [0x74, 0x65, 0x64, 0x62, 0x79, 0x74, 0x65, 0x73];
        $subkey = array_chunk($k, 8);
        self::_reverse64($subkey[0]);
        self::_xor64(self::$v0, $subkey[0]);
        self::_xor64(self::$v2, $subkey[0]);
        self::_reverse64($subkey[1]);
        self::_xor64(self::$v1, $subkey[1]);
        self::_xor64(self::$v3, $subkey[1]);

        self::$m_idx = 7;
        self::$msg_byte_counter = 0;
        $exp = str_split($str);
        for ($i = 0; $i < count($exp); $i++) {
            self::updateHash(ord($exp[$i]));
        }
        $msgLen = self::$msg_byte_counter;
        while (self::$m_idx > 0) {
            self::updateHash(0);
        }
        self::updateHash($msgLen);

        self::$v2[7] ^= 0xff; //	xor_ff(v2);
        self::$v2[7] &= self::UINT8_MASK;

        self::siphash_round();
        self::siphash_round();
        self::siphash_round();
        self::siphash_round();

        self::_xor64(self::$v0, self::$v1);
        self::_xor64(self::$v0, self::$v2);
        self::_xor64(self::$v0, self::$v3);
        //var_dump($v0);
        $result = sprintf("%02X%02X%02X%02X%02X%02X%02X%02X", self::$v0[0], self::$v0[1], self::$v0[2], self::$v0[3], self::$v0[4], self::$v0[5], self::$v0[6], self::$v0[7]);

        return $result;//uc : bin2hex($truc);
    }

    protected static function updateHash($c) {

        self::$msg_byte_counter++; // count this one % 256
        self::$m[self::$m_idx--] = $c;
        if (self::$m_idx < 0) {
            self::$m_idx = 7; // reset index
            // hash this 64 bits
            self::_xor64(self::$v3, self::$m);
            self::siphash_round();
            self::siphash_round();
            self::_xor64(self::$v0, self::$m);

        }

    }

    protected static function siphash_round() {

        self::_add64(self::$v0, self::$v1);
        self::_add64(self::$v2, self::$v3);
        self::_rol_13bits(self::$v1);
        self::_rotl64_16(self::$v3);

        self::_xor64(self::$v1, self::$v0);
        self::_xor64(self::$v3, self::$v2);
        self::_rotl64_32(self::$v0);

        self::_add64(self::$v2, self::$v1);
        self::_add64(self::$v0, self::$v3);
        self::_rol_17bits(self::$v1);
        self::_rol_21bits(self::$v3);

        self::_xor64(self::$v1, self::$v2);
        self::_xor64(self::$v3, self::$v0);
        self::_rotl64_32(self::$v2);
    }

    protected static function _xor64(&$a, $b) {
        for ($i = 0; $i < 8; $i++) {
            $a[$i] ^= $b[$i];
            $a[$i] &= self::UINT8_MASK;
        }
    }

    protected static function _rotl64_16(&$v) {
        $v0 = $v[0];
        $v1 = $v[1];
        for ($i = 0; $i < 6; $i++) {
            $v[$i] = $v[$i + 2];
        }
        $v[6] = $v0;
        $v[7] = $v1;
    }

    protected static function _rotl64_32(&$v) {
        for ($i = 0; $i < 4; $i++) {
            $vTemp = $v[$i];
            $v[$i] = $v[$i + 4];
            $v[$i + 4] = $vTemp;
        }
    }

    protected static function _reverse64(&$x) {
        for ($i = 0; $i < 4; $i++) {
            $xTemp = $x[$i];
            $x[$i] = $x[7 - $i];
            $x[7 - $i] = $xTemp;
        }

    }

    protected static function _add64(&$v, $s) {
        $carry = 0;


        for ($i = 7; $i >= 0; $i--) {
            $carry += $v[$i];
            $carry += $s[$i];
            $v[$i] = $carry;
            $v[$i] &= self::UINT8_MASK;
            $carry = ($carry >> 8) & self::UINT8_MASK;
        }

    }

    protected static function _rotl64_xbits(&$v, $x) {
        $v0 = $v[0];
        for ($i = 0; $i < 7; $i++) {
            $v[$i] = ($v[$i] << ($x)) | ($v[$i + 1] >> (8 - ($x)));
            $v[$i] &= self::UINT8_MASK;
        }
        $v[7] = ($v[7] << ($x)) | ($v0 >> (8 - ($x)));
        $v[7] &= self::UINT8_MASK;
    }

    protected static function _rotr64_xbits(&$v, $x) {
        $v7 = $v[7];
        for ($i = 7; $i > 0; $i--) {
            $v[$i] = ($v[$i] >> ($x)) | ($v[$i - 1] << (8 - ($x)));
            $v[$i] &= self::UINT8_MASK;
        }
        $v[0] = ($v[0] >> ($x)) | ($v7 << (8 - ($x)));
        $v[0] &= self::UINT8_MASK;
    }

    protected static function _rol_17bits(&$v) {
        self::_rotl64_16($v);
        self::_rotl64_xbits($v, 1);
    }

    protected static function _rol_21bits(&$v) {
        self::_rotl64_16($v);
        self::_rotl64_xbits($v, 5);
    }

    protected static function _rol_13bits(&$v) {
        self::_rotl64_16($v);
        self::_rotr64_xbits($v, 3);
    }


}

function siphash_2_4($key, $str) {
    SipHash::hash($key, $str);
}

?>
