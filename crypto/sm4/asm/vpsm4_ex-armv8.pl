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

my @vtmpxx=map("v$_",(16..25)); #16 17 18 19  20 21 22 23  24 25
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

	&sbox_lookup(@vtmp[0],@$src,@vtmp[1]);
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
&gen_sm4_xts($prefix);

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
