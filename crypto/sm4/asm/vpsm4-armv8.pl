#! /usr/bin/env perl
# Copyright 2020-2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# This module implements SM4 with ASIMD on aarch64
#
# Feb 2022
#

# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

push(@INC,"${dir}.");
require "vpsm4-armv8-common.pl";

$prefix="vpsm4";

my @sbox=map("v$_",(16..31));

sub sbox_lookup() {
	my $des = shift;
	my $src = shift;
	my $tmp = shift;
$code.=<<___;
	tbl	$des.16b,{@sbox[0].16b,@sbox[1].16b,@sbox[2].16b,@sbox[3].16b},$src.16b
	sub	$src.16b,$src.16b,@vtmp[0].16b
	tbx	$des.16b,{@sbox[4].16b,@sbox[5].16b,@sbox[6].16b,@sbox[7].16b},$src.16b
	sub	$src.16b,$src.16b,@vtmp[0].16b
	tbx	$des.16b,{@sbox[8].16b,@sbox[9].16b,@sbox[10].16b,@sbox[11].16b},$src.16b
	sub	$src.16b,$src.16b,@vtmp[0].16b
	tbx	$des.16b,{@sbox[12].16b,@sbox[13].16b,@sbox[14].16b,@sbox[15].16b},$src.16b
___
}

# sbox operations for 4-lane of words
sub sbox() {
	my $dat = shift;

$code.=<<___;
	movi	@vtmp[0].16b,#64
	movi	@vtmp[1].16b,#128
	movi	@vtmp[2].16b,#192
	sub	@vtmp[0].16b,$dat.16b,@vtmp[0].16b
	sub	@vtmp[1].16b,$dat.16b,@vtmp[1].16b
	sub	@vtmp[2].16b,$dat.16b,@vtmp[2].16b
	tbl	$dat.16b,{@sbox[0].16b,@sbox[1].16b,@sbox[2].16b,@sbox[3].16b},$dat.16b
	tbl	@vtmp[0].16b,{@sbox[4].16b,@sbox[5].16b,@sbox[6].16b,@sbox[7].16b},@vtmp[0].16b
	tbl	@vtmp[1].16b,{@sbox[8].16b,@sbox[9].16b,@sbox[10].16b,@sbox[11].16b},@vtmp[1].16b
	tbl	@vtmp[2].16b,{@sbox[12].16b,@sbox[13].16b,@sbox[14].16b,@sbox[15].16b},@vtmp[2].16b
	add	@vtmp[0].2d,@vtmp[0].2d,@vtmp[1].2d
	add	@vtmp[2].2d,@vtmp[2].2d,$dat.2d
	add	$dat.2d,@vtmp[0].2d,@vtmp[2].2d

	ushr	@vtmp[0].4s,$dat.4s,32-2
	sli	@vtmp[0].4s,$dat.4s,2
	ushr	@vtmp[2].4s,$dat.4s,32-10
	eor	@vtmp[1].16b,@vtmp[0].16b,$dat.16b
	sli	@vtmp[2].4s,$dat.4s,10
	eor	@vtmp[1].16b,@vtmp[2].16b,$vtmp[1].16b
	ushr	@vtmp[0].4s,$dat.4s,32-18
	sli	@vtmp[0].4s,$dat.4s,18
	ushr	@vtmp[2].4s,$dat.4s,32-24
	eor	@vtmp[1].16b,@vtmp[0].16b,$vtmp[1].16b
	sli	@vtmp[2].4s,$dat.4s,24
	eor	$dat.16b,@vtmp[2].16b,@vtmp[1].16b
___
}

# sbox operation for 8-lane of words
sub sbox_double() {
	my $dat = shift;
	my $datx = shift;

$code.=<<___;
	movi	@vtmp[3].16b,#64
	sub	@vtmp[0].16b,$dat.16b,@vtmp[3].16b
	sub	@vtmp[1].16b,@vtmp[0].16b,@vtmp[3].16b
	sub	@vtmp[2].16b,@vtmp[1].16b,@vtmp[3].16b
	tbl	$dat.16b,{@sbox[0].16b,@sbox[1].16b,@sbox[2].16b,@sbox[3].16b},$dat.16b
	tbl	@vtmp[0].16b,{@sbox[4].16b,@sbox[5].16b,@sbox[6].16b,@sbox[7].16b},@vtmp[0].16b
	tbl	@vtmp[1].16b,{@sbox[8].16b,@sbox[9].16b,@sbox[10].16b,@sbox[11].16b},@vtmp[1].16b
	tbl	@vtmp[2].16b,{@sbox[12].16b,@sbox[13].16b,@sbox[14].16b,@sbox[15].16b},@vtmp[2].16b
	add	@vtmp[1].2d,@vtmp[0].2d,@vtmp[1].2d
	add	$dat.2d,@vtmp[2].2d,$dat.2d
	add	$dat.2d,@vtmp[1].2d,$dat.2d

	sub	@vtmp[0].16b,$datx.16b,@vtmp[3].16b
	sub	@vtmp[1].16b,@vtmp[0].16b,@vtmp[3].16b
	sub	@vtmp[2].16b,@vtmp[1].16b,@vtmp[3].16b
	tbl	$datx.16b,{@sbox[0].16b,@sbox[1].16b,@sbox[2].16b,@sbox[3].16b},$datx.16b
	tbl	@vtmp[0].16b,{@sbox[4].16b,@sbox[5].16b,@sbox[6].16b,@sbox[7].16b},@vtmp[0].16b
	tbl	@vtmp[1].16b,{@sbox[8].16b,@sbox[9].16b,@sbox[10].16b,@sbox[11].16b},@vtmp[1].16b
	tbl	@vtmp[2].16b,{@sbox[12].16b,@sbox[13].16b,@sbox[14].16b,@sbox[15].16b},@vtmp[2].16b
	add	@vtmp[1].2d,@vtmp[0].2d,@vtmp[1].2d
	add	$datx.2d,@vtmp[2].2d,$datx.2d
	add	$datx.2d,@vtmp[1].2d,$datx.2d

	ushr	@vtmp[0].4s,$dat.4s,32-2
	sli	@vtmp[0].4s,$dat.4s,2
	ushr	@vtmp[2].4s,$datx.4s,32-2
	eor	@vtmp[1].16b,@vtmp[0].16b,$dat.16b
	sli	@vtmp[2].4s,$datx.4s,2

	ushr	@vtmp[0].4s,$dat.4s,32-10
	eor	@vtmp[3].16b,@vtmp[2].16b,$datx.16b
	sli	@vtmp[0].4s,$dat.4s,10
	ushr	@vtmp[2].4s,$datx.4s,32-10
	eor	@vtmp[1].16b,@vtmp[0].16b,$vtmp[1].16b
	sli	@vtmp[2].4s,$datx.4s,10

	ushr	@vtmp[0].4s,$dat.4s,32-18
	eor	@vtmp[3].16b,@vtmp[2].16b,$vtmp[3].16b
	sli	@vtmp[0].4s,$dat.4s,18
	ushr	@vtmp[2].4s,$datx.4s,32-18
	eor	@vtmp[1].16b,@vtmp[0].16b,$vtmp[1].16b
	sli	@vtmp[2].4s,$datx.4s,18

	ushr	@vtmp[0].4s,$dat.4s,32-24
	eor	@vtmp[3].16b,@vtmp[2].16b,$vtmp[3].16b
	sli	@vtmp[0].4s,$dat.4s,24
	ushr	@vtmp[2].4s,$datx.4s,32-24
	eor	$dat.16b,@vtmp[0].16b,@vtmp[1].16b
	sli	@vtmp[2].4s,$datx.4s,24
	eor	$datx.16b,@vtmp[2].16b,@vtmp[3].16b
___
}

# sbox operation for one single word
sub sbox_1word() {
	my $word = shift;

$code.=<<___;
	movi	@vtmp[1].16b,#64
	movi	@vtmp[2].16b,#128
	movi	@vtmp[3].16b,#192
	mov	@vtmp[0].s[0],$word

	sub	@vtmp[1].16b,@vtmp[0].16b,@vtmp[1].16b
	sub	@vtmp[2].16b,@vtmp[0].16b,@vtmp[2].16b
	sub	@vtmp[3].16b,@vtmp[0].16b,@vtmp[3].16b

	tbl	@vtmp[0].16b,{@sbox[0].16b,@sbox[1].16b,@sbox[2].16b,@sbox[3].16b},@vtmp[0].16b
	tbl	@vtmp[1].16b,{@sbox[4].16b,@sbox[5].16b,@sbox[6].16b,@sbox[7].16b},@vtmp[1].16b
	tbl	@vtmp[2].16b,{@sbox[8].16b,@sbox[9].16b,@sbox[10].16b,@sbox[11].16b},@vtmp[2].16b
	tbl	@vtmp[3].16b,{@sbox[12].16b,@sbox[13].16b,@sbox[14].16b,@sbox[15].16b},@vtmp[3].16b

	mov	$word,@vtmp[0].s[0]
	mov	$wtmp0,@vtmp[1].s[0]
	mov	$wtmp2,@vtmp[2].s[0]
	add	$wtmp0,$word,$wtmp0
	mov	$word,@vtmp[3].s[0]
	add	$wtmp0,$wtmp0,$wtmp2
	add	$wtmp0,$wtmp0,$word

	eor	$word,$wtmp0,$wtmp0,ror #32-2
	eor	$word,$word,$wtmp0,ror #32-10
	eor	$word,$word,$wtmp0,ror #32-18
	eor	$word,$word,$wtmp0,ror #32-24
___
}

sub load_sbox() {
	my $data = shift;

$code.=<<___;
	adr	$ptr,.Lsbox
	ld1	{@sbox[0].4s,@sbox[1].4s,@sbox[2].4s,@sbox[3].4s},[$ptr],#64
	ld1	{@sbox[4].4s,@sbox[5].4s,@sbox[6].4s,@sbox[7].4s},[$ptr],#64
	ld1	{@sbox[8].4s,@sbox[9].4s,@sbox[10].4s,@sbox[11].4s},[$ptr],#64
	ld1	{@sbox[12].4s,@sbox[13].4s,@sbox[14].4s,@sbox[15].4s},[$ptr]
___
}

$code=<<___;
#include "arm_arch.h"
.arch	armv8-a
.text

.type	_vpsm4_consts,%object
.align	7
_vpsm4_consts:
.Lsbox:
	.byte 0xD6,0x90,0xE9,0xFE,0xCC,0xE1,0x3D,0xB7,0x16,0xB6,0x14,0xC2,0x28,0xFB,0x2C,0x05
	.byte 0x2B,0x67,0x9A,0x76,0x2A,0xBE,0x04,0xC3,0xAA,0x44,0x13,0x26,0x49,0x86,0x06,0x99
	.byte 0x9C,0x42,0x50,0xF4,0x91,0xEF,0x98,0x7A,0x33,0x54,0x0B,0x43,0xED,0xCF,0xAC,0x62
	.byte 0xE4,0xB3,0x1C,0xA9,0xC9,0x08,0xE8,0x95,0x80,0xDF,0x94,0xFA,0x75,0x8F,0x3F,0xA6
	.byte 0x47,0x07,0xA7,0xFC,0xF3,0x73,0x17,0xBA,0x83,0x59,0x3C,0x19,0xE6,0x85,0x4F,0xA8
	.byte 0x68,0x6B,0x81,0xB2,0x71,0x64,0xDA,0x8B,0xF8,0xEB,0x0F,0x4B,0x70,0x56,0x9D,0x35
	.byte 0x1E,0x24,0x0E,0x5E,0x63,0x58,0xD1,0xA2,0x25,0x22,0x7C,0x3B,0x01,0x21,0x78,0x87
	.byte 0xD4,0x00,0x46,0x57,0x9F,0xD3,0x27,0x52,0x4C,0x36,0x02,0xE7,0xA0,0xC4,0xC8,0x9E
	.byte 0xEA,0xBF,0x8A,0xD2,0x40,0xC7,0x38,0xB5,0xA3,0xF7,0xF2,0xCE,0xF9,0x61,0x15,0xA1
	.byte 0xE0,0xAE,0x5D,0xA4,0x9B,0x34,0x1A,0x55,0xAD,0x93,0x32,0x30,0xF5,0x8C,0xB1,0xE3
	.byte 0x1D,0xF6,0xE2,0x2E,0x82,0x66,0xCA,0x60,0xC0,0x29,0x23,0xAB,0x0D,0x53,0x4E,0x6F
	.byte 0xD5,0xDB,0x37,0x45,0xDE,0xFD,0x8E,0x2F,0x03,0xFF,0x6A,0x72,0x6D,0x6C,0x5B,0x51
	.byte 0x8D,0x1B,0xAF,0x92,0xBB,0xDD,0xBC,0x7F,0x11,0xD9,0x5C,0x41,0x1F,0x10,0x5A,0xD8
	.byte 0x0A,0xC1,0x31,0x88,0xA5,0xCD,0x7B,0xBD,0x2D,0x74,0xD0,0x12,0xB8,0xE5,0xB4,0xB0
	.byte 0x89,0x69,0x97,0x4A,0x0C,0x96,0x77,0x7E,0x65,0xB9,0xF1,0x09,0xC5,0x6E,0xC6,0x84
	.byte 0x18,0xF0,0x7D,0xEC,0x3A,0xDC,0x4D,0x20,0x79,0xEE,0x5F,0x3E,0xD7,0xCB,0x39,0x48
.Lck:
	.long 0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269
	.long 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9
	.long 0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249
	.long 0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9
	.long 0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229
	.long 0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299
	.long 0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209
	.long 0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
.Lfk:
	.dword 0x56aa3350a3b1bac6,0xb27022dc677d9197
.Lshuffles:
	.dword 0x0B0A090807060504,0x030201000F0E0D0C

.size	_vpsm4_consts,.-_vpsm4_consts
___

&gen_sm4_set_key($prefix);
&gen_sm4_block_cipher($prefix);
&gen_sm4_ecb($prefix);
&gen_sm4_cbc($prefix);
&gen_sm4_ctr($prefix);
########################################
open SELF,$0;
while(<SELF>) {
        next if (/^#!/);
        last if (!s/^#/\/\// and !/^$/);
        print;
}
close SELF;

foreach(split("\n",$code)) {
	s/\`([^\`]*)\`/eval($1)/ge;
	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
