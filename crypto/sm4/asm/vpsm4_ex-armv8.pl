#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

#
# This module implements SM4 with ASIMD and AESE on AARCH64
#
# Dec 2022
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

$prefix="vpsm4_ex";

my ($vtmp4,$vtmp5)=("v24","v25");
my ($MaskV,$TAHMatV,$TALMatV,$ATAHMatV,$ATALMatV,$ANDMaskV)=("v26","v27","v28","v29","v30","v31");
my ($MaskQ,$TAHMatQ,$TALMatQ,$ATAHMatQ,$ATALMatQ,$ANDMaskQ)=("q26","q27","q28","q29","q30","q31");

# matrix multiplication Mat*x = (lowerMat*x) ^ (higherMat*x)
sub mul_matrix() {
	my $x = shift;
	my $higherMat = shift;
	my $lowerMat = shift;
	my $tmp = shift;
$code.=<<___;
	ushr	$tmp.16b, $x.16b, 4
	and		$x.16b, $x.16b, $ANDMaskV.16b
	tbl		$x.16b, {$lowerMat.16b}, $x.16b
	tbl		$tmp.16b, {$higherMat.16b}, $tmp.16b
	eor		$x.16b, $x.16b, $tmp.16b
___
}
# optimize sbox using AESE instruction
sub sbox_lookup() {
	my $des = shift;
	my $src = shift;
	my $tmp = shift;
$code.=<<___;
	tbl	$des.16b, {$src.16b}, $MaskV.16b
___
	&mul_matrix($des, $TAHMatV, $TALMatV, @vtmp[2]);
$code.=<<___;
	eor $tmp.16b, $tmp.16b, $tmp.16b
	aese $des.16b,$tmp.16b
___
	&mul_matrix($des, $ATAHMatV, $ATALMatV, @vtmp[2]);
}
# sbox operation for one single word
sub sbox_1word() {
	my $word = shift;

$code.=<<___;
	mov	@vtmp[3].s[0],$word
___
	&sbox_lookup(@vtmp[0],@vtmp[3],@vtmp[1]);
$code.=<<___;
	mov	$wtmp0,@vtmp[0].s[0]
	eor	$word,$wtmp0,$wtmp0,ror #32-2
	eor	$word,$word,$wtmp0,ror #32-10
	eor	$word,$word,$wtmp0,ror #32-18
	eor	$word,$word,$wtmp0,ror #32-24
___
}

# sbox operation for 4-lane of words
sub sbox() {
	my $src = shift;

	&sbox_lookup(@vtmp[0],$src,@vtmp[1]);
$code.=<<___;
	mov	$src.16b,@vtmp[0].16b
	// linear transformation
	// todo: src <-> @vtmp[0]
	ushr	@vtmp[0].4s,$src.4s,32-2
	ushr	@vtmp[1].4s,$src.4s,32-10
	ushr	@vtmp[2].4s,$src.4s,32-18
	ushr	@vtmp[3].4s,$src.4s,32-24
	sli	@vtmp[0].4s,$src.4s,2
	sli	@vtmp[1].4s,$src.4s,10
	sli	@vtmp[2].4s,$src.4s,18
	sli	@vtmp[3].4s,$src.4s,24
	eor	$vtmp4.16b,@vtmp[0].16b,$src.16b
	eor	$vtmp4.16b,$vtmp4.16b,$vtmp[1].16b
	eor	$src.16b,@vtmp[2].16b,@vtmp[3].16b
	eor	$src.16b,$src.16b,$vtmp4.16b
___
}

# sbox operation for 8-lane of words
sub sbox_double() {
	my $dat = shift;
	my $datx = shift;

$code.=<<___;
	// optimize sbox using AESE instruction
	tbl	@vtmp[0].16b, {$dat.16b}, $MaskV.16b
	tbl	@vtmp[1].16b, {$datx.16b}, $MaskV.16b
___
	&mul_matrix(@vtmp[0], $TAHMatV, $TALMatV, $vtmp4);
	&mul_matrix(@vtmp[1], $TAHMatV, $TALMatV, $vtmp4);
$code.=<<___;
	eor $vtmp5.16b, $vtmp5.16b, $vtmp5.16b
	aese @vtmp[0].16b,$vtmp5.16b
	aese @vtmp[1].16b,$vtmp5.16b
___
	&mul_matrix(@vtmp[0], $ATAHMatV, $ATALMatV,$vtmp4);
	&mul_matrix(@vtmp[1], $ATAHMatV, $ATALMatV,$vtmp4);
$code.=<<___;
	mov	$dat.16b,@vtmp[0].16b
	mov	$datx.16b,@vtmp[1].16b

	// linear transformation
	ushr	@vtmp[0].4s,$dat.4s,32-2
	ushr	$vtmp5.4s,$datx.4s,32-2
	ushr	@vtmp[1].4s,$dat.4s,32-10
	ushr	@vtmp[2].4s,$dat.4s,32-18
	ushr	@vtmp[3].4s,$dat.4s,32-24
	sli	@vtmp[0].4s,$dat.4s,2
	sli	$vtmp5.4s,$datx.4s,2
	sli	@vtmp[1].4s,$dat.4s,10
	sli	@vtmp[2].4s,$dat.4s,18
	sli	@vtmp[3].4s,$dat.4s,24
	eor	$vtmp4.16b,@vtmp[0].16b,$dat.16b
	eor	$vtmp4.16b,$vtmp4.16b,@vtmp[1].16b
	eor	$dat.16b,@vtmp[2].16b,@vtmp[3].16b
	eor	$dat.16b,$dat.16b,$vtmp4.16b
	ushr	@vtmp[1].4s,$datx.4s,32-10
	ushr	@vtmp[2].4s,$datx.4s,32-18
	ushr	@vtmp[3].4s,$datx.4s,32-24
	sli	@vtmp[1].4s,$datx.4s,10
	sli	@vtmp[2].4s,$datx.4s,18
	sli	@vtmp[3].4s,$datx.4s,24
	eor	$vtmp4.16b,$vtmp5.16b,$datx.16b
	eor	$vtmp4.16b,$vtmp4.16b,@vtmp[1].16b
	eor	$datx.16b,@vtmp[2].16b,@vtmp[3].16b
	eor	$datx.16b,$datx.16b,$vtmp4.16b
___
}

sub load_sbox () {
$code.=<<___;
	ldr $MaskQ,	   =0x0306090c0f0205080b0e0104070a0d00
	ldr $TAHMatQ,	=0x22581a6002783a4062185a2042387a00
	ldr $TALMatQ,	=0xc10bb67c4a803df715df62a89e54e923
	ldr $ATAHMatQ,   =0x1407c6d56c7fbeadb9aa6b78c1d21300
	ldr $ATALMatQ,   =0xe383c1a1fe9edcbc6404462679195b3b
	ldr $ANDMaskQ,	=0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f
___
}

$code=<<___;
#include "arm_arch.h"
.arch	armv8-a+crypto
.text

.type	_${prefix}_consts,%object
.align	7
_${prefix}_consts:
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
	.long 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc
.Lshuffles:
	.long 0x07060504, 0x0B0A0908, 0x0F0E0D0C, 0x03020100
 
.size	_${prefix}_consts,.-_${prefix}_consts
___

&gen_sm4_set_key($prefix);
&gen_sm4_block_cipher($prefix);
&gen_sm4_ecb($prefix);
&gen_sm4_cbc($prefix);
&gen_sm4_ctr($prefix);

# x0: in
# x1: out
# x2: len
# x3: key1
# x4: key2
# x5: iv
# x6: enc/dec
sub gen_xts_cipher() {
	my $prefix = shift;

	my ($inp,$outp)=("x0","x1");
	my ($blocks,$len)=("w2","w2");
	my ($rks,$rks1,$rks2)=("x3","x3","x4");
	my ($ivp,$enc)=("x5","w6");
	my $remain=("w7");
	my ($tmpw,$tmp,$wtmp0,$wtmp1,$wtmp2)=("w8","x8","w9","w10","w11");
	my ($xtmp1,$xtmp2)=("x10","x11");
	my ($ptr,$counter)=("x12","w13");
	my ($word0,$word1,$word2,$word3)=("w14","w15","w16","w17");

	my @twx=map("x$_",(14..29));
	my $lastBlk=("x26");

	my @tweak=map("v$_",(8..15));

$code.=<<___;
.globl	${prefix}_xts_encrypt${standard}
.type	${prefix}_xts_encrypt${standard},%function
.align	5
${prefix}_xts_encrypt${standard}:
	AARCH64_SIGN_LINK_REGISTER
	stp		x15, x16, [sp, #-0x10]!
	stp		x17, x18, [sp, #-0x10]!
	stp		x19, x20, [sp, #-0x10]!
	stp		x21, x22, [sp, #-0x10]!
	stp		x23, x24, [sp, #-0x10]!
	stp		x25, x26, [sp, #-0x10]!
	stp		x27, x28, [sp, #-0x10]!
	stp		x29, x30, [sp, #-0x10]!
	stp		d8, d9, [sp, #-0x10]!
	stp		d10, d11, [sp, #-0x10]!
	stp		d12, d13, [sp, #-0x10]!
	stp		d14, d15, [sp, #-0x10]!
	ld1	{@tweak[0].4s}, [$ivp]
	mov	$rks,$rks2
___
	&load_sbox();
	&rev32(@tweak[0],@tweak[0]);
	&encrypt_1blk(@tweak[0]);
$code.=<<___;
	mov	$rks,$rks1
	and	$remain,$len,#0x0F
	// convert length into blocks
	lsr	$blocks,$len,4
	cmp	$blocks,#1
	b.lt .return${standard}

	cmp $remain,0
	// If the encryption/decryption Length is N times of 16,
	// the all blocks are encrypted/decrypted in .xts_encrypt_blocks${standard}
	b.eq .xts_encrypt_blocks${standard}

	// If the encryption/decryption length is not N times of 16,
	// the last two blocks are encrypted/decrypted in .last_2blks_tweak${standard} or .only_2blks_tweak${standard}
	// the other blocks are encrypted/decrypted in .xts_encrypt_blocks${standard}
	subs $blocks,$blocks,#1
	b.eq .only_2blks_tweak${standard}
.xts_encrypt_blocks${standard}:
___
	&rbit(@tweak[0],@tweak[0]);
	&rev32_armeb(@tweak[0],@tweak[0]);
	&mov_vec_to_reg(@tweak[0],@twx[0],@twx[1]);
	&compute_tweak(@twx[0],@twx[1],@twx[2],@twx[3]);
	&compute_tweak(@twx[2],@twx[3],@twx[4],@twx[5]);
	&compute_tweak(@twx[4],@twx[5],@twx[6],@twx[7]);
	&compute_tweak(@twx[6],@twx[7],@twx[8],@twx[9]);
	&compute_tweak(@twx[8],@twx[9],@twx[10],@twx[11]);
	&compute_tweak(@twx[10],@twx[11],@twx[12],@twx[13]);
	&compute_tweak(@twx[12],@twx[13],@twx[14],@twx[15]);
$code.=<<___;
.Lxts_8_blocks_process${standard}:
	cmp	$blocks,#8
___
	&mov_reg_to_vec(@twx[0],@twx[1],@tweak[0]);
	&compute_tweak(@twx[14],@twx[15],@twx[0],@twx[1]);
	&mov_reg_to_vec(@twx[2],@twx[3],@tweak[1]);
	&compute_tweak(@twx[0],@twx[1],@twx[2],@twx[3]);
	&mov_reg_to_vec(@twx[4],@twx[5],@tweak[2]);
	&compute_tweak(@twx[2],@twx[3],@twx[4],@twx[5]);
	&mov_reg_to_vec(@twx[6],@twx[7],@tweak[3]);
	&compute_tweak(@twx[4],@twx[5],@twx[6],@twx[7]);
	&mov_reg_to_vec(@twx[8],@twx[9],@tweak[4]);
	&compute_tweak(@twx[6],@twx[7],@twx[8],@twx[9]);
	&mov_reg_to_vec(@twx[10],@twx[11],@tweak[5]);
	&compute_tweak(@twx[8],@twx[9],@twx[10],@twx[11]);
	&mov_reg_to_vec(@twx[12],@twx[13],@tweak[6]);
	&compute_tweak(@twx[10],@twx[11],@twx[12],@twx[13]);
	&mov_reg_to_vec(@twx[14],@twx[15],@tweak[7]);
	&compute_tweak(@twx[12],@twx[13],@twx[14],@twx[15]);
$code.=<<___;
	b.lt	.Lxts_4_blocks_process${standard}
	ld1 {@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
___
	&rbit(@tweak[0],@tweak[0]);
	&rbit(@tweak[1],@tweak[1]);
	&rbit(@tweak[2],@tweak[2]);
	&rbit(@tweak[3],@tweak[3]);
$code.=<<___;
	// note @tweak[0..3] and @datax[0..3] are resuing the same register
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	eor @data[1].16b, @data[1].16b, @tweak[1].16b
	eor @data[2].16b, @data[2].16b, @tweak[2].16b
	eor @data[3].16b, @data[3].16b, @tweak[3].16b
	ld1	{@datax[0].4s,$datax[1].4s,@datax[2].4s,@datax[3].4s},[$inp],#64
___
	&rbit(@tweak[4],@tweak[4]);
	&rbit(@tweak[5],@tweak[5]);
	&rbit(@tweak[6],@tweak[6]);
	&rbit(@tweak[7],@tweak[7]);
$code.=<<___;
	// note @tweak[4..7] and @vtmpx[0..3] are resuing the same register
	eor @datax[0].16b, @datax[0].16b, @tweak[4].16b
	eor @datax[1].16b, @datax[1].16b, @tweak[5].16b
	eor @datax[2].16b, @datax[2].16b, @tweak[6].16b
	eor @datax[3].16b, @datax[3].16b, @tweak[7].16b
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
	&rev32(@datax[0],@datax[0]);
	&rev32(@datax[1],@datax[1]);
	&rev32(@datax[2],@datax[2]);
	&rev32(@datax[3],@datax[3]);
	&transpose(@data,@vtmp);
	&transpose(@datax,@vtmp);
$code.=<<___;
	bl	_vpsm4_enc_8blks
___
	&transpose(@vtmp,@datax);
	&transpose(@data,@datax);
	&mov_reg_to_vec(@twx[0],@twx[1],@tweak[0]);
	&mov_reg_to_vec(@twx[2],@twx[3],@tweak[1]);
	&mov_reg_to_vec(@twx[4],@twx[5],@tweak[2]);
	&mov_reg_to_vec(@twx[6],@twx[7],@tweak[3]);
	&mov_reg_to_vec(@twx[8],@twx[9],@tweak[4]);
	&mov_reg_to_vec(@twx[10],@twx[11],@tweak[5]);
	&mov_reg_to_vec(@twx[12],@twx[13],@tweak[6]);
	&mov_reg_to_vec(@twx[14],@twx[15],@tweak[7]);
$code.=<<___;
	// note @tweak[0..3] and @datax[0..3] are resuing the same register
	// note @tweak[4..7] and @vtmpx[0..3] are resuing the same register
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	eor @vtmp[2].16b, @vtmp[2].16b, @tweak[2].16b
	eor @vtmp[3].16b, @vtmp[3].16b, @tweak[3].16b
	eor @data[0].16b, @data[0].16b, @tweak[4].16b
	eor @data[1].16b, @data[1].16b, @tweak[5].16b
	eor @data[2].16b, @data[2].16b, @tweak[6].16b
	eor @data[3].16b, @data[3].16b, @tweak[7].16b

	// save the last tweak
	st1	{@tweak[7].16b},[$ivp]
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	st1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$outp],#64
	subs	$blocks,$blocks,#8
	b.gt	.Lxts_8_blocks_process${standard}
	b	100f
.Lxts_4_blocks_process${standard}:
	cmp	$blocks,#4
	b.lt	1f
	ld1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
___
	&rbit(@tweak[0],@tweak[0]);
	&rbit(@tweak[1],@tweak[1]);
	&rbit(@tweak[2],@tweak[2]);
	&rbit(@tweak[3],@tweak[3]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	eor @data[1].16b, @data[1].16b, @tweak[1].16b
	eor @data[2].16b, @data[2].16b, @tweak[2].16b
	eor @data[3].16b, @data[3].16b, @tweak[3].16b
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
	&transpose(@data,@vtmp);
$code.=<<___;
	bl	_vpsm4_enc_4blks
___
	&transpose(@vtmp,@data);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	eor @vtmp[2].16b, @vtmp[2].16b, @tweak[2].16b
	eor @vtmp[3].16b, @vtmp[3].16b, @tweak[3].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	sub	$blocks,$blocks,#4
	mov @tweak[0].16b,@tweak[4].16b
	mov @tweak[1].16b,@tweak[5].16b
	mov @tweak[2].16b,@tweak[6].16b
	// save the last tweak
	st1	{@tweak[3].16b},[$ivp]
1:
	// process last block
	cmp	$blocks,#1
	b.lt	100f
	b.gt	1f
	ld1	{@data[0].4s},[$inp],#16
___
	&rbit(@tweak[0],@tweak[0]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
___
	&rev32(@data[0],@data[0]);
	&encrypt_1blk(@data[0]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	st1	{@data[0].4s},[$outp],#16
	// save the last tweak
	st1	{@tweak[0].16b},[$ivp]
	b	100f
1:  // process last 2 blocks
	cmp	$blocks,#2
	b.gt	1f
	ld1	{@data[0].4s,@data[1].4s},[$inp],#32
___
	&rbit(@tweak[0],@tweak[0]);
	&rbit(@tweak[1],@tweak[1]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	eor @data[1].16b, @data[1].16b, @tweak[1].16b
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&transpose(@data,@vtmp);
$code.=<<___;
	bl	_vpsm4_enc_4blks
___
	&transpose(@vtmp,@data);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s},[$outp],#32
	// save the last tweak
	st1	{@tweak[1].16b},[$ivp]
	b	100f
1:  // process last 3 blocks
	ld1	{@data[0].4s,@data[1].4s,@data[2].4s},[$inp],#48
___
	&rbit(@tweak[0],@tweak[0]);
	&rbit(@tweak[1],@tweak[1]);
	&rbit(@tweak[2],@tweak[2]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	eor @data[1].16b, @data[1].16b, @tweak[1].16b
	eor @data[2].16b, @data[2].16b, @tweak[2].16b
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&transpose(@data,@vtmp);
$code.=<<___;
	bl	_vpsm4_enc_4blks
___
	&transpose(@vtmp,@data);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	eor @vtmp[2].16b, @vtmp[2].16b, @tweak[2].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s},[$outp],#48
	// save the last tweak
	st1	{@tweak[2].16b},[$ivp]
100:
	cmp $remain,0
	b.eq .return${standard}

// This brance calculates the last two tweaks, 
// while the encryption/decryption length is larger than 32
.last_2blks_tweak${standard}:
	ld1	{@tweak[7].16b},[$ivp]
___
	&rev32_armeb(@tweak[7],@tweak[7]);
	&compute_tweak_vec(@tweak[1],@tweak[7]);
	&compute_tweak_vec(@tweak[2],@tweak[1]);
$code.=<<___;
	b .check_dec${standard}


// This brance calculates the last two tweaks, 
// while the encryption/decryption length is equal to 32, who only need two tweaks
.only_2blks_tweak${standard}:
	mov @tweak[1].16b,@tweak[0].16b
___
	&rev32_armeb(@tweak[1],@tweak[1]);
	&compute_tweak_vec(@tweak[2],@tweak[1]);
$code.=<<___;
	b .check_dec${standard}


// Determine whether encryption or decryption is required.
// The last two tweaks need to be swapped for decryption.
.check_dec${standard}:
	// encryption:1 decryption:0
	cmp $enc,1
	b.eq .prcess_last_2blks${standard}
	mov @vtmp[0].16B,@tweak[1].16b
	mov @tweak[1].16B,@tweak[2].16b
	mov @tweak[2].16B,@vtmp[0].16b

.prcess_last_2blks${standard}:
___
	&rev32_armeb(@tweak[1],@tweak[1]);
	&rev32_armeb(@tweak[2],@tweak[2]);
$code.=<<___;
	ld1	{@data[0].4s},[$inp],#16
	eor @data[0].16b, @data[0].16b, @tweak[1].16b
___
	&rev32(@data[0],@data[0]);
	&encrypt_1blk(@data[0]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[1].16b
	st1	{@data[0].4s},[$outp],#16

	sub $lastBlk,$outp,16
	.loop${standard}:
		subs $remain,$remain,1
		ldrb	$wtmp0,[$lastBlk,$remain]
		ldrb	$wtmp1,[$inp,$remain]
		strb	$wtmp1,[$lastBlk,$remain]
		strb	$wtmp0,[$outp,$remain]
	b.gt .loop${standard}
	ld1		{@data[0].4s}, [$lastBlk]	
	eor @data[0].16b, @data[0].16b, @tweak[2].16b
___
	&rev32(@data[0],@data[0]);
	&encrypt_1blk(@data[0]);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[2].16b
	st1		{@data[0].4s}, [$lastBlk]
.return${standard}:
	ldp		d14, d15, [sp], #0x10
	ldp		d12, d13, [sp], #0x10
	ldp		d10, d11, [sp], #0x10
	ldp		d8, d9, [sp], #0x10
	ldp		x29, x30, [sp], #0x10
	ldp		x27, x28, [sp], #0x10
	ldp		x25, x26, [sp], #0x10
	ldp		x23, x24, [sp], #0x10
	ldp		x21, x22, [sp], #0x10
	ldp		x19, x20, [sp], #0x10
	ldp		x17, x18, [sp], #0x10
	ldp		x15, x16, [sp], #0x10
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_xts_encrypt${standard},.-${prefix}_xts_encrypt${standard}
___
} # end of gen_xts_cipher
$standard = "_gb";
&gen_xts_cipher($prefix);
$standard = "";
&gen_xts_cipher($prefix);


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
