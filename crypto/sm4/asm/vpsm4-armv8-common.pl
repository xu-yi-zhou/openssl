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

@vtmp=map("v$_",(0..3));
@qtmp=map("q$_",(0..3));
@data=map("v$_",(4..7));
@datax=map("v$_",(8..11));
($rk0,$rk1)=("v12","v13");
($rka,$rkb)=("v14","v15");
@vtmpx=map("v$_",(12..15));

($inp,$outp,$blocks,$rks)=("x0","x1","w2","x3");
($tmpw,$tmp,$wtmp0,$wtmp1,$wtmp2)=("w6","x6","w7","w8","w9");
($ptr,$counter)=("x10","w11");
($word0,$word1,$word2,$word3)=("w12","w13","w14","w15");

sub rev32() {
	my $dst = shift;
	my $src = shift;

	if ($src and ("$src" ne "$dst")) {
$code.=<<___;
#ifndef __ARMEB__
	rev32	$dst.16b,$src.16b
#else
	mov	$dst.16b,$src.16b
#endif
___
	} else {
$code.=<<___;
#ifndef __ARMEB__
	rev32	$dst.16b,$dst.16b
#endif
___
	}
}

sub rev32_armeb() {
	my $dst = shift;
	my $src = shift;

	if ($src and ("$src" ne "$dst")) {
$code.=<<___;
#ifdef __ARMEB__
	rev32	$dst.16b,$src.16b
#else
	mov	$dst.16b,$src.16b
#endif
___
	} else {
$code.=<<___;
#ifdef __ARMEB__
	rev32	$dst.16b,$dst.16b
#endif
___
	}
}

sub transpose() {
	my ($dat0,$dat1,$dat2,$dat3,$vt0,$vt1,$vt2,$vt3) = @_;

$code.=<<___;
	zip1	$vt0.4s,$dat0.4s,$dat1.4s
	zip2	$vt1.4s,$dat0.4s,$dat1.4s
	zip1	$vt2.4s,$dat2.4s,$dat3.4s
	zip2	$vt3.4s,$dat2.4s,$dat3.4s
	zip1	$dat0.2d,$vt0.2d,$vt2.2d
	zip2	$dat1.2d,$vt0.2d,$vt2.2d
	zip1	$dat2.2d,$vt1.2d,$vt3.2d
	zip2	$dat3.2d,$vt1.2d,$vt3.2d
___
}

# sm4 for one block of data, in scalar registers word0/word1/word2/word3
sub sm4_1blk() {
	my $kptr = shift;

$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	$tmpw,$word2,$word3
	eor	$wtmp2,$wtmp0,$word1
	eor	$tmpw,$tmpw,$wtmp2
___
	&sbox_1word($tmpw);
$code.=<<___;
	eor	$word0,$word0,$tmpw
	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	$tmpw,$word2,$word3
	eor	$wtmp2,$word0,$wtmp1
	eor	$tmpw,$tmpw,$wtmp2
___
	&sbox_1word($tmpw);
$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	eor	$word1,$word1,$tmpw
	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	$tmpw,$word0,$word1
	eor	$wtmp2,$wtmp0,$word3
	eor	$tmpw,$tmpw,$wtmp2
___
	&sbox_1word($tmpw);
$code.=<<___;
	eor	$word2,$word2,$tmpw
	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	$tmpw,$word0,$word1
	eor	$wtmp2,$word2,$wtmp1
	eor	$tmpw,$tmpw,$wtmp2
___
	&sbox_1word($tmpw);
$code.=<<___;
	eor	$word3,$word3,$tmpw
___
}

# sm4 for 4-lanes of data, in neon registers data0/data1/data2/data3
sub sm4_4blks() {
	my $kptr = shift;

$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	dup	$rk0.4s,$wtmp0
	dup	$rk1.4s,$wtmp1

	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	eor	$rka.16b,@data[2].16b,@data[3].16b
	eor	$rk0.16b,@data[1].16b,$rk0.16b
	eor	$rk0.16b,$rka.16b,$rk0.16b
___
	&sbox($rk0);
$code.=<<___;
	eor	@data[0].16b,@data[0].16b,$rk0.16b

	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	eor	$rka.16b,$rka.16b,@data[0].16b
	eor	$rk1.16b,$rka.16b,$rk1.16b
___
	&sbox($rk1);
$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	eor	@data[1].16b,@data[1].16b,$rk1.16b

	dup	$rk0.4s,$wtmp0
	dup	$rk1.4s,$wtmp1

	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	eor	$rka.16b,@data[0].16b,@data[1].16b
	eor	$rk0.16b,@data[3].16b,$rk0.16b
	eor	$rk0.16b,$rka.16b,$rk0.16b
___
	&sbox($rk0);
$code.=<<___;
	eor	@data[2].16b,@data[2].16b,$rk0.16b

	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	eor	$rka.16b,$rka.16b,@data[2].16b
	eor	$rk1.16b,$rka.16b,$rk1.16b
___
	&sbox($rk1);
$code.=<<___;
	eor	@data[3].16b,@data[3].16b,$rk1.16b
___
}

# sm4 for 8 lanes of data, in neon registers
# data0/data1/data2/data3 datax0/datax1/datax2/datax3
sub sm4_8blks() {
	my $kptr = shift;

$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	// B0 ^= SBOX(B1 ^ B2 ^ B3 ^ RK0)
	dup	$rk0.4s,$wtmp0
	eor	$rka.16b,@data[2].16b,@data[3].16b
	eor	$rkb.16b,@datax[2].16b,@datax[3].16b
	eor	@vtmp[0].16b,@data[1].16b,$rk0.16b
	eor	@vtmp[1].16b,@datax[1].16b,$rk0.16b
	eor	$rk0.16b,$rka.16b,@vtmp[0].16b
	eor	$rk1.16b,$rkb.16b,@vtmp[1].16b
___
	&sbox_double($rk0,$rk1);
$code.=<<___;
	eor	@data[0].16b,@data[0].16b,$rk0.16b
	eor	@datax[0].16b,@datax[0].16b,$rk1.16b

	// B1 ^= SBOX(B0 ^ B2 ^ B3 ^ RK1)
	dup	$rk1.4s,$wtmp1
	eor	$rka.16b,$rka.16b,@data[0].16b
	eor	$rkb.16b,$rkb.16b,@datax[0].16b
	eor	$rk0.16b,$rka.16b,$rk1.16b
	eor	$rk1.16b,$rkb.16b,$rk1.16b
___
	&sbox_double($rk0,$rk1);
$code.=<<___;
	ldp	$wtmp0,$wtmp1,[$kptr],8
	eor	@data[1].16b,@data[1].16b,$rk0.16b
	eor	@datax[1].16b,@datax[1].16b,$rk1.16b

	// B2 ^= SBOX(B0 ^ B1 ^ B3 ^ RK2)
	dup	$rk0.4s,$wtmp0
	eor	$rka.16b,@data[0].16b,@data[1].16b
	eor	$rkb.16b,@datax[0].16b,@datax[1].16b
	eor	@vtmp[0].16b,@data[3].16b,$rk0.16b
	eor	@vtmp[1].16b,@datax[3].16b,$rk0.16b
	eor	$rk0.16b,$rka.16b,@vtmp[0].16b
	eor	$rk1.16b,$rkb.16b,@vtmp[1].16b
___
	&sbox_double($rk0,$rk1);
$code.=<<___;
	eor	@data[2].16b,@data[2].16b,$rk0.16b
	eor	@datax[2].16b,@datax[2].16b,$rk1.16b

	// B3 ^= SBOX(B0 ^ B1 ^ B2 ^ RK3)
	dup	$rk1.4s,$wtmp1
	eor	$rka.16b,$rka.16b,@data[2].16b
	eor	$rkb.16b,$rkb.16b,@datax[2].16b
	eor	$rk0.16b,$rka.16b,$rk1.16b
	eor	$rk1.16b,$rkb.16b,$rk1.16b
___
	&sbox_double($rk0,$rk1);
$code.=<<___;
	eor	@data[3].16b,@data[3].16b,$rk0.16b
	eor	@datax[3].16b,@datax[3].16b,$rk1.16b
___
}


sub encrypt_1blk_norev() {
	my $dat = shift;

$code.=<<___;
	mov	$ptr,$rks
	mov	$counter,#8
	mov	$word0,$dat.s[0]
	mov	$word1,$dat.s[1]
	mov	$word2,$dat.s[2]
	mov	$word3,$dat.s[3]
10:
___
	&sm4_1blk($ptr);
$code.=<<___;
	subs	$counter,$counter,#1
	b.ne	10b
	mov	$dat.s[0],$word3
	mov	$dat.s[1],$word2
	mov	$dat.s[2],$word1
	mov	$dat.s[3],$word0
___
}

sub encrypt_1blk() {
	my $dat = shift;

	&encrypt_1blk_norev($dat);
	&rev32($dat,$dat);
}

sub encrypt_4blks() {
$code.=<<___;
	mov	$ptr,$rks
	mov	$counter,#8
10:
___
	&sm4_4blks($ptr);
$code.=<<___;
	subs	$counter,$counter,#1
	b.ne	10b
___
	&rev32(@vtmp[3],@data[0]);
	&rev32(@vtmp[2],@data[1]);
	&rev32(@vtmp[1],@data[2]);
	&rev32(@vtmp[0],@data[3]);
}

sub encrypt_8blks() {
$code.=<<___;
	mov	$ptr,$rks
	mov	$counter,#8
10:
___
	&sm4_8blks($ptr);
$code.=<<___;
	subs	$counter,$counter,#1
	b.ne	10b
___
	&rev32(@vtmp[3],@data[0]);
	&rev32(@vtmp[2],@data[1]);
	&rev32(@vtmp[1],@data[2]);
	&rev32(@vtmp[0],@data[3]);
	&rev32(@data[3],@datax[0]);
	&rev32(@data[2],@datax[1]);
	&rev32(@data[1],@datax[2]);
	&rev32(@data[0],@datax[3]);
}

sub mov_reg_to_vec() {
	my $src0 = shift;
	my $src1 = shift;
	my $desv = shift;
$code.=<<___;
	mov $desv.d[0],$src0
	mov $desv.d[1],$src1
#ifdef __ARMEB__
	rev32  $desv.16b,$desv.16b
#endif
___
}

sub mov_vec_to_reg() {
	my $srcv = shift;
	my $des0 = shift;
	my $des1 = shift;
$code.=<<___;
	mov $des0,$srcv.d[0]
	mov $des1,$srcv.d[1]
___
}

sub compute_tweak() {
	my $src0 = shift;
	my $src1 = shift;
	my $des0 = shift;
	my $des1 = shift;
$code.=<<___;
	mov $wtmp0,0x87
	extr	$xtmp2,$src1,$src1,#32
	extr	$des1,$src1,$src0,#63
	and	$wtmp1,$wtmp0,$wtmp2,asr#31
	eor	$des0,$xtmp1,$src0,lsl#1
___
}

sub compute_tweak_vec() {
	my $src = shift;
	my $des = shift;
	&rbit(@vtmp[2],$src);
$code.=<<___;
	ldr  @qtmp[0], =0x01010101010101010101010101010187
	shl  $des.16b, @vtmp[2].16b, #1
	ext  @vtmp[1].16b, @vtmp[2].16b, @vtmp[2].16b,#15
	ushr @vtmp[1].16b, @vtmp[1].16b, #7
	mul  @vtmp[1].16b, @vtmp[1].16b, @vtmp[0].16b
	eor  $des.16b, $des.16b, @vtmp[1].16b
___
	&rbit($des,$des);
}

sub rbit() {
	my $dst = shift;
	my $src = shift;

	if ($src and ("$src" ne "$dst")) {
		if ($standard eq "_gb") {
$code.=<<___;
			rbit $dst.16b,$src.16b
___
		} else {
$code.=<<___;
			mov $dst.16b,$src.16b
___
		}
	} else {
		if ($standard eq "_gb") {
$code.=<<___;
			rbit $dst.16b,$src.16b
___
		}
	}
}


sub gen_sm4_set_key() {
	my $prefix = shift;
	my ($key,$keys,$enc)=("x0","x1","w2");
	my ($pointer,$schedules,$wtmp,$roundkey)=("x5","x6","w7","w8");
	my ($vkey,$vfk,$vmap)=("v5","v6","v7");

$code.=<<___;
.type	_vpsm4_set_key,%function
.align	4
_vpsm4_set_key:
	AARCH64_VALID_CALL_TARGET
	ld1	{$vkey.4s},[$key]
___
	&load_sbox();
	&rev32($vkey,$vkey);
$code.=<<___;
	adr	$pointer,.Lshuffles
	ld1	{$vmap.4s},[$pointer]
	adr	$pointer,.Lfk
	ld1	{$vfk.4s},[$pointer]
	eor	$vkey.16b,$vkey.16b,$vfk.16b
	mov	$schedules,#32
	adr	$pointer,.Lck
	movi	@vtmp[0].16b,#64
	cbnz	$enc,1f
	add	$keys,$keys,124
1:
	mov	$wtmp,$vkey.s[1]
	ldr	$roundkey,[$pointer],#4
	eor	$roundkey,$roundkey,$wtmp
	mov	$wtmp,$vkey.s[2]
	eor	$roundkey,$roundkey,$wtmp
	mov	$wtmp,$vkey.s[3]
	eor	$roundkey,$roundkey,$wtmp
	// sbox lookup
	mov	@data[0].s[0],$roundkey
___
	&sbox_lookup(@vtmp[1],@data[0],@vtmp[0]);
$code.=<<___;
	mov	$wtmp,@vtmp[1].s[0]
	eor	$roundkey,$wtmp,$wtmp,ror #19
	eor	$roundkey,$roundkey,$wtmp,ror #9
	mov	$wtmp,$vkey.s[0]
	eor	$roundkey,$roundkey,$wtmp
	mov	$vkey.s[0],$roundkey
	cbz	$enc,2f
	str	$roundkey,[$keys],#4
	b	3f
2:
	str	$roundkey,[$keys],#-4
3:
	tbl	$vkey.16b,{$vkey.16b},$vmap.16b
	subs	$schedules,$schedules,#1
	b.ne	1b
	ret
.size	_vpsm4_set_key,.-_vpsm4_set_key

.type	_vpsm4_enc_4blks,%function
.align	4
_vpsm4_enc_4blks:
	AARCH64_VALID_CALL_TARGET
___
	&encrypt_4blks();
$code.=<<___;
	ret
.size	_vpsm4_enc_4blks,.-_vpsm4_enc_4blks

.type	_vpsm4_enc_8blks,%function
.align	4
_vpsm4_enc_8blks:
	AARCH64_VALID_CALL_TARGET
___
	&encrypt_8blks();
$code.=<<___;
	ret
.size	_vpsm4_enc_8blks,.-_vpsm4_enc_8blks

.globl	${prefix}_set_encrypt_key
.type	${prefix}_set_encrypt_key,%function
.align	5
${prefix}_set_encrypt_key:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-16]!
	mov	w2,1
	bl	_vpsm4_set_key
	ldp	x29,x30,[sp],#16
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_set_encrypt_key,.-${prefix}_set_encrypt_key

.globl	${prefix}_set_decrypt_key
.type	${prefix}_set_decrypt_key,%function
.align	5
${prefix}_set_decrypt_key:
	AARCH64_SIGN_LINK_REGISTER
	stp	x29,x30,[sp,#-16]!
	mov	w2,0
	bl	_vpsm4_set_key
	ldp	x29,x30,[sp],#16
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_set_decrypt_key,.-${prefix}_set_decrypt_key
___
}

sub gen_block() {
	my $dir = shift;
	my ($inp,$outp,$rk)=map("x$_",(0..2));

$code.=<<___;
.globl	${prefix}_${dir}crypt
.type	${prefix}_${dir}crypt,%function
.align	5
${prefix}_${dir}crypt:
	AARCH64_VALID_CALL_TARGET
	ld1	{@data[0].16b},[$inp]
___
	&load_sbox();
	&rev32(@data[0],@data[0]);
$code.=<<___;
	mov	$rks,x2
___
	&encrypt_1blk(@data[0]);
$code.=<<___;
	st1	{@data[0].16b},[$outp]
	ret
.size	${prefix}_${dir}crypt,.-${prefix}_${dir}crypt
___
}

sub gen_sm4_block_cipher() {
	my $prefix = shift;

	&gen_block("en",$prefix);
	&gen_block("de",$prefix);
___
}

sub gen_sm4_ecb() {
	my $prefix = shift;
$code.=<<___;
.globl	${prefix}_ecb_encrypt
.type	${prefix}_ecb_encrypt,%function
.align	5
${prefix}_ecb_encrypt:
	AARCH64_SIGN_LINK_REGISTER
	// convert length into blocks
	lsr	x2,x2,4
	stp	d8,d9,[sp,#-80]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]
	stp	x29,x30,[sp,#64]
___
	&load_sbox();
$code.=<<___;
.Lecb_8_blocks_process:
	cmp	$blocks,#8
	b.lt	.Lecb_4_blocks_process
	ld4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
	ld4	{@datax[0].4s,$datax[1].4s,@datax[2].4s,@datax[3].4s},[$inp],#64
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
	&rev32(@datax[0],@datax[0]);
	&rev32(@datax[1],@datax[1]);
	&rev32(@datax[2],@datax[2]);
	&rev32(@datax[3],@datax[3]);
$code.=<<___;
	bl	_vpsm4_enc_8blks
	st4	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	st4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$outp],#64
	subs	$blocks,$blocks,#8
	b.gt	.Lecb_8_blocks_process
	b	100f
.Lecb_4_blocks_process:
	cmp	$blocks,#4
	b.lt	1f
	ld4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	st4	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	sub	$blocks,$blocks,#4
1:
	// process last block
	cmp	$blocks,#1
	b.lt	100f
	b.gt	1f
	ld1	{@data[0].16b},[$inp]
___
	&rev32(@data[0],@data[0]);
	&encrypt_1blk(@data[0]);
$code.=<<___;
	st1	{@data[0].16b},[$outp]
	b	100f
1:	// process last 2 blocks
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[0],[$inp],#16
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[1],[$inp],#16
	cmp	$blocks,#2
	b.gt	1f
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	st4	{@vtmp[0].s-@vtmp[3].s}[0],[$outp],#16
	st4	{@vtmp[0].s-@vtmp[3].s}[1],[$outp]
	b	100f
1:	// process last 3 blocks
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[2],[$inp],#16
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	st4	{@vtmp[0].s-@vtmp[3].s}[0],[$outp],#16
	st4	{@vtmp[0].s-@vtmp[3].s}[1],[$outp],#16
	st4	{@vtmp[0].s-@vtmp[3].s}[2],[$outp]
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	x29,x30,[sp,#64]
	ldp	d8,d9,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_ecb_encrypt,.-${prefix}_ecb_encrypt
___
}

sub gen_sm4_cbc() {
	my $prefix = shift;
	my ($len,$ivp,$enc)=("x2","x4","w5");
	my $ivec0=("v3");
	my $ivec1=("v15");

$code.=<<___;
.globl	${prefix}_cbc_encrypt
.type	${prefix}_cbc_encrypt,%function
.align	5
${prefix}_cbc_encrypt:
	AARCH64_VALID_CALL_TARGET
	lsr	$len,$len,4
___
	&load_sbox();
$code.=<<___;
	cbz	$enc,.Ldec
	ld1	{$ivec0.4s},[$ivp]
.Lcbc_4_blocks_enc:
	cmp	$blocks,#4
	b.lt	1f
	ld1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
	eor	@data[0].16b,@data[0].16b,$ivec0.16b
___
	&rev32(@data[1],@data[1]);
	&rev32(@data[0],@data[0]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
	&encrypt_1blk_norev(@data[0]);
$code.=<<___;
	eor	@data[1].16b,@data[1].16b,@data[0].16b
___
	&encrypt_1blk_norev(@data[1]);
	&rev32(@data[0],@data[0]);

$code.=<<___;
	eor	@data[2].16b,@data[2].16b,@data[1].16b
___
	&encrypt_1blk_norev(@data[2]);
	&rev32(@data[1],@data[1]);
$code.=<<___;
	eor	@data[3].16b,@data[3].16b,@data[2].16b
___
	&encrypt_1blk_norev(@data[3]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	orr	$ivec0.16b,@data[3].16b,@data[3].16b
	st1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$outp],#64
	subs	$blocks,$blocks,#4
	b.ne	.Lcbc_4_blocks_enc
	b	2f
1:
	subs	$blocks,$blocks,#1
	b.lt	2f
	ld1	{@data[0].4s},[$inp],#16
	eor	$ivec0.16b,$ivec0.16b,@data[0].16b
___
	&rev32($ivec0,$ivec0);
	&encrypt_1blk($ivec0);
$code.=<<___;
	st1	{$ivec0.16b},[$outp],#16
	b	1b
2:
	// save back IV
	st1	{$ivec0.16b},[$ivp]
	ret

.Ldec:
	// decryption mode starts
	AARCH64_SIGN_LINK_REGISTER
	stp	d8,d9,[sp,#-80]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]
	stp	x29,x30,[sp,#64]
.Lcbc_8_blocks_dec:
	cmp	$blocks,#8
	b.lt	1f
	ld4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp]
	add	$ptr,$inp,#64
	ld4	{@datax[0].4s,@datax[1].4s,@datax[2].4s,@datax[3].4s},[$ptr]
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],$data[3]);
	&rev32(@datax[0],@datax[0]);
	&rev32(@datax[1],@datax[1]);
	&rev32(@datax[2],@datax[2]);
	&rev32(@datax[3],$datax[3]);
$code.=<<___;
	bl	_vpsm4_enc_8blks
___
	&transpose(@vtmp,@datax);
	&transpose(@data,@datax);
$code.=<<___;
	ld1	{$ivec1.16b},[$ivp]
	ld1	{@datax[0].4s,@datax[1].4s,@datax[2].4s,@datax[3].4s},[$inp],#64
	// note ivec1 and vtmpx[3] are resuing the same register
	// care needs to be taken to avoid conflict
	eor	@vtmp[0].16b,@vtmp[0].16b,$ivec1.16b
	ld1	{@vtmpx[0].4s,@vtmpx[1].4s,@vtmpx[2].4s,@vtmpx[3].4s},[$inp],#64
	eor	@vtmp[1].16b,@vtmp[1].16b,@datax[0].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@datax[1].16b
	eor	@vtmp[3].16b,$vtmp[3].16b,@datax[2].16b
	// save back IV
	st1	{$vtmpx[3].16b}, [$ivp]
	eor	@data[0].16b,@data[0].16b,$datax[3].16b
	eor	@data[1].16b,@data[1].16b,@vtmpx[0].16b
	eor	@data[2].16b,@data[2].16b,@vtmpx[1].16b
	eor	@data[3].16b,$data[3].16b,@vtmpx[2].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	st1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$outp],#64
	subs	$blocks,$blocks,#8
	b.gt	.Lcbc_8_blocks_dec
	b.eq	100f
1:
	ld1	{$ivec1.16b},[$ivp]
.Lcbc_4_blocks_dec:
	cmp	$blocks,#4
	b.lt	1f
	ld4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp]
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],$data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	ld1	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$inp],#64
___
	&transpose(@vtmp,@datax);
$code.=<<___;
	eor	@vtmp[0].16b,@vtmp[0].16b,$ivec1.16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@data[0].16b
	orr	$ivec1.16b,@data[3].16b,@data[3].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@data[1].16b
	eor	@vtmp[3].16b,$vtmp[3].16b,@data[2].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	subs	$blocks,$blocks,#4
	b.gt	.Lcbc_4_blocks_dec
	// save back IV
	st1	{@data[3].16b}, [$ivp]
	b	100f
1:	// last block
	subs	$blocks,$blocks,#1
	b.lt	100f
	b.gt	1f
	ld1	{@data[0].4s},[$inp],#16
	// save back IV
	st1	{$data[0].16b}, [$ivp]
___
	&rev32(@datax[0],@data[0]);
	&encrypt_1blk(@datax[0]);
$code.=<<___;
	eor	@datax[0].16b,@datax[0].16b,$ivec1.16b
	st1	{@datax[0].16b},[$outp],#16
	b	100f
1:	// last two blocks
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[0],[$inp]
	add	$ptr,$inp,#16
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[1],[$ptr],#16
	subs	$blocks,$blocks,1
	b.gt	1f
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	ld1	{@data[0].4s,@data[1].4s},[$inp],#32
___
	&transpose(@vtmp,@datax);
$code.=<<___;
	eor	@vtmp[0].16b,@vtmp[0].16b,$ivec1.16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@data[0].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s},[$outp],#32
	// save back IV
	st1	{@data[1].16b}, [$ivp]
	b	100f
1:	// last 3 blocks
	ld4	{@data[0].s,@data[1].s,@data[2].s,@data[3].s}[2],[$ptr]
___
	&rev32(@data[0],@data[0]);
	&rev32(@data[1],@data[1]);
	&rev32(@data[2],@data[2]);
	&rev32(@data[3],@data[3]);
$code.=<<___;
	bl	_vpsm4_enc_4blks
	ld1	{@data[0].4s,@data[1].4s,@data[2].4s},[$inp],#48
___
	&transpose(@vtmp,@datax);
$code.=<<___;
	eor	@vtmp[0].16b,@vtmp[0].16b,$ivec1.16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@data[0].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@data[1].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s},[$outp],#48
	// save back IV
	st1	{@data[2].16b}, [$ivp]
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	x29,x30,[sp,#64]
	ldp	d8,d9,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_cbc_encrypt,.-${prefix}_cbc_encrypt
___
}

sub gen_sm4_ctr() {
	my $prefix = shift;
	my ($ivp,$ctr)=("x4","w5");
	my $ivec=("v3");

$code.=<<___;
.globl	${prefix}_ctr32_encrypt_blocks
.type	${prefix}_ctr32_encrypt_blocks,%function
.align	5
${prefix}_ctr32_encrypt_blocks:
	AARCH64_VALID_CALL_TARGET
	ld1	{$ivec.4s},[$ivp]
___
	&rev32($ivec,$ivec);
	&load_sbox();
$code.=<<___;
	cmp	$blocks,#1
	b.ne	1f
	// fast processing for one single block without
	// context saving overhead
___
	&encrypt_1blk($ivec);
$code.=<<___;
	ld1	{@data[0].16b},[$inp]
	eor	@data[0].16b,@data[0].16b,$ivec.16b
	st1	{@data[0].16b},[$outp]
	ret
1:
	AARCH64_SIGN_LINK_REGISTER
	stp	d8,d9,[sp,#-80]!
	stp	d10,d11,[sp,#16]
	stp	d12,d13,[sp,#32]
	stp	d14,d15,[sp,#48]
	stp	x29,x30,[sp,#64]
	mov	$word0,$ivec.s[0]
	mov	$word1,$ivec.s[1]
	mov	$word2,$ivec.s[2]
	mov	$ctr,$ivec.s[3]
.Lctr32_4_blocks_process:
	cmp	$blocks,#4
	b.lt	1f
	dup	@data[0].4s,$word0
	dup	@data[1].4s,$word1
	dup	@data[2].4s,$word2
	mov	@data[3].s[0],$ctr
	add	$ctr,$ctr,#1
	mov	$data[3].s[1],$ctr
	add	$ctr,$ctr,#1
	mov	@data[3].s[2],$ctr
	add	$ctr,$ctr,#1
	mov	@data[3].s[3],$ctr
	add	$ctr,$ctr,#1
	cmp	$blocks,#8
	b.ge	.Lctr32_8_blocks_process
	bl	_vpsm4_enc_4blks
	ld4	{@vtmpx[0].4s,@vtmpx[1].4s,@vtmpx[2].4s,@vtmpx[3].4s},[$inp],#64
	eor	@vtmp[0].16b,@vtmp[0].16b,@vtmpx[0].16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@vtmpx[1].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@vtmpx[2].16b
	eor	@vtmp[3].16b,@vtmp[3].16b,@vtmpx[3].16b
	st4	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	subs	$blocks,$blocks,#4
	b.ne	.Lctr32_4_blocks_process
	b	100f
.Lctr32_8_blocks_process:
	dup	@datax[0].4s,$word0
	dup	@datax[1].4s,$word1
	dup	@datax[2].4s,$word2
	mov	@datax[3].s[0],$ctr
	add	$ctr,$ctr,#1
	mov	$datax[3].s[1],$ctr
	add	$ctr,$ctr,#1
	mov	@datax[3].s[2],$ctr
	add	$ctr,$ctr,#1
	mov	@datax[3].s[3],$ctr
	add	$ctr,$ctr,#1
	bl	_vpsm4_enc_8blks
	ld4	{@vtmpx[0].4s,@vtmpx[1].4s,@vtmpx[2].4s,@vtmpx[3].4s},[$inp],#64
	ld4	{@datax[0].4s,@datax[1].4s,@datax[2].4s,@datax[3].4s},[$inp],#64
	eor	@vtmp[0].16b,@vtmp[0].16b,@vtmpx[0].16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@vtmpx[1].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@vtmpx[2].16b
	eor	@vtmp[3].16b,@vtmp[3].16b,@vtmpx[3].16b
	eor	@data[0].16b,@data[0].16b,@datax[0].16b
	eor	@data[1].16b,@data[1].16b,@datax[1].16b
	eor	@data[2].16b,@data[2].16b,@datax[2].16b
	eor	@data[3].16b,@data[3].16b,@datax[3].16b
	st4	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s,@vtmp[3].4s},[$outp],#64
	st4	{@data[0].4s,@data[1].4s,@data[2].4s,@data[3].4s},[$outp],#64
	subs	$blocks,$blocks,#8
	b.ne	.Lctr32_4_blocks_process
	b	100f
1:	// last block processing
	subs	$blocks,$blocks,#1
	b.lt	100f
	b.gt	1f
	mov	$ivec.s[0],$word0
	mov	$ivec.s[1],$word1
	mov	$ivec.s[2],$word2
	mov	$ivec.s[3],$ctr
___
	&encrypt_1blk($ivec);
$code.=<<___;
	ld1	{@data[0].16b},[$inp]
	eor	@data[0].16b,@data[0].16b,$ivec.16b
	st1	{@data[0].16b},[$outp]
	b	100f
1:	// last 2 blocks processing
	dup	@data[0].4s,$word0
	dup	@data[1].4s,$word1
	dup	@data[2].4s,$word2
	mov	@data[3].s[0],$ctr
	add	$ctr,$ctr,#1
	mov	@data[3].s[1],$ctr
	subs	$blocks,$blocks,#1
	b.ne	1f
	bl	_vpsm4_enc_4blks
	ld4	{@vtmpx[0].s,@vtmpx[1].s,@vtmpx[2].s,@vtmpx[3].s}[0],[$inp],#16
	ld4	{@vtmpx[0].s,@vtmpx[1].s,@vtmpx[2].s,@vtmpx[3].s}[1],[$inp],#16
	eor	@vtmp[0].16b,@vtmp[0].16b,@vtmpx[0].16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@vtmpx[1].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@vtmpx[2].16b
	eor	@vtmp[3].16b,@vtmp[3].16b,@vtmpx[3].16b
	st4	{@vtmp[0].s,@vtmp[1].s,@vtmp[2].s,@vtmp[3].s}[0],[$outp],#16
	st4	{@vtmp[0].s,@vtmp[1].s,@vtmp[2].s,@vtmp[3].s}[1],[$outp],#16
	b	100f
1:	// last 3 blocks processing
	add	$ctr,$ctr,#1
	mov	@data[3].s[2],$ctr
	bl	_vpsm4_enc_4blks
	ld4	{@vtmpx[0].s,@vtmpx[1].s,@vtmpx[2].s,@vtmpx[3].s}[0],[$inp],#16
	ld4	{@vtmpx[0].s,@vtmpx[1].s,@vtmpx[2].s,@vtmpx[3].s}[1],[$inp],#16
	ld4	{@vtmpx[0].s,@vtmpx[1].s,@vtmpx[2].s,@vtmpx[3].s}[2],[$inp],#16
	eor	@vtmp[0].16b,@vtmp[0].16b,@vtmpx[0].16b
	eor	@vtmp[1].16b,@vtmp[1].16b,@vtmpx[1].16b
	eor	@vtmp[2].16b,@vtmp[2].16b,@vtmpx[2].16b
	eor	@vtmp[3].16b,@vtmp[3].16b,@vtmpx[3].16b
	st4	{@vtmp[0].s,@vtmp[1].s,@vtmp[2].s,@vtmp[3].s}[0],[$outp],#16
	st4	{@vtmp[0].s,@vtmp[1].s,@vtmp[2].s,@vtmp[3].s}[1],[$outp],#16
	st4	{@vtmp[0].s,@vtmp[1].s,@vtmp[2].s,@vtmp[3].s}[2],[$outp],#16
100:
	ldp	d10,d11,[sp,#16]
	ldp	d12,d13,[sp,#32]
	ldp	d14,d15,[sp,#48]
	ldp	x29,x30,[sp,#64]
	ldp	d8,d9,[sp],#80
	AARCH64_VALIDATE_LINK_REGISTER
	ret
.size	${prefix}_ctr32_encrypt_blocks,.-${prefix}_ctr32_encrypt_blocks
___
}

# void vpsm4_ex_xts_encrypt(const unsigned char *in, unsigned char *out,
#						   size_t len, const void *key1, const void *key2,
#						   const unsigned char ivec[16], const int enc);
# void vpsm4_ex_xts_encrypt_gb(const unsigned char *in, unsigned char *out,
#						   size_t len, const void *key1, const void *key2,
#						   const unsigned char ivec[16], const int enc);
# x0: in
# x1: out
# x2: len
# x3: key1
# x4: key2
# x5: iv
# x6: enc/dec
# todo: encrypt_1blk=>delete rks
sub gen_xts_cipher() {
	my $standard = shift;
	my $prefix = shift;

	my ($inp,$outp,$blocks,$rks)=("x0","x1","w2","x3");
	my ($tmpw,$tmp,$wtmp0,$wtmp1,$wtmp2)=("w8","x8","w9","w10","w11");
	my ($xtmp1,$xtmp2)=("x10","x11");
	my ($ptr,$counter)=("x12","w13");
	my ($word0,$word1,$word2,$word3)=("w14","w15","w16","w17");

	my ($rks1,$rks2)=("x3","x4");
	my ($blocks,$len)=("w2","w2");
	my $remain=("x7");
	my @twx=map("x$_",(14..29));
	my $lastBlk=("x26");

	my @tweak=map("v$_",(0..7));
	my $lastTweak=("v25");

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
	bl	${prefix}_enc_8blks
___
	&transpose(@vtmp,@datax);
	&transpose(@data,@datax);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	eor @vtmp[2].16b, @vtmp[2].16b, @tweak[2].16b
	eor @vtmp[3].16b, @vtmp[3].16b, @tweak[3].16b
	eor @data[0].16b, @data[0].16b, @tweak[4].16b
	eor @data[1].16b, @data[1].16b, @tweak[5].16b
	eor @data[2].16b, @data[2].16b, @tweak[6].16b
	eor @data[3].16b, @data[3].16b, @tweak[7].16b

	// save the last tweak
	mov $lastTweak.16b,@tweak[7].16b
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
	bl	${prefix}_enc_4blks
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
	mov $lastTweak.16b,@tweak[3].16b
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
	&encrypt_1blk(@data[0],$rks1);
$code.=<<___;
	eor @data[0].16b, @data[0].16b, @tweak[0].16b
	st1	{@data[0].4s},[$outp],#16
	// save the last tweak
	mov $lastTweak.16b,@tweak[0].16b
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
	bl	${prefix}_enc_4blks
___
	&transpose(@vtmp,@data);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s},[$outp],#32
	// save the last tweak
	mov $lastTweak.16b,@tweak[1].16b
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
	bl	${prefix}_enc_4blks
___
	&transpose(@vtmp,@data);
$code.=<<___;
	eor @vtmp[0].16b, @vtmp[0].16b, @tweak[0].16b
	eor @vtmp[1].16b, @vtmp[1].16b, @tweak[1].16b
	eor @vtmp[2].16b, @vtmp[2].16b, @tweak[2].16b
	st1	{@vtmp[0].4s,@vtmp[1].4s,@vtmp[2].4s},[$outp],#48
	// save the last tweak
	mov $lastTweak.16b,@tweak[2].16b
100:
	cmp $remain,0
	b.eq .return${standard}

// This brance calculates the last two tweaks, 
// while the encryption/decryption length is larger than 32
.last_2blks_tweak${standard}:
___
	&rev32_armeb($lastTweak,$lastTweak);
	&compute_tweak_vec($lastTweak,@tweak[1]);
	&compute_tweak_vec(@tweak[1],@tweak[2]);
$code.=<<___;
	b .check_dec${standard}


// This brance calculates the last two tweaks, 
// while the encryption/decryption length is equal to 32, who only need two tweaks
.only_2blks_tweak${standard}:
	mov @tweak[1].16b,@tweak[0].16b
___
	&rev32_armeb(@tweak[1],@tweak[1]);
	&compute_tweak_vec(@tweak[1],@tweak[2]);
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
	&encrypt_1blk(@data[0],$rks1);
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
	&encrypt_1blk(@data[0],$rks1);
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

sub gen_sm4_xts(){
	my $prefix = shift;

	&gen_xts_cipher("_gb",$prefix);
	&gen_xts_cipher("",$prefix);
}