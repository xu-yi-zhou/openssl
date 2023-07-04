#! /usr/bin/env perl
# Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

$flavour = shift;
while (($output=shift) && ($output!~/\w[\w\-]*\.\w+$/)) {}

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}arm-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/arm-xlate.pl" and -f $xlate) or
die "can't locate arm-xlate.pl";

open OUT,"| \"$^X\" $xlate $flavour $output";
*STDOUT=*OUT;

sub bn_mod_add() {
	my $mod = shift;
$code.=<<___;
	/* Load inputs */
	ldp	x3,x4,[x1]
	ldp	x5,x6,[x1,#0x10]
	/* Addition */
	ldp	x7,x8,[x2]
	ldp	x9,x10,[x2,#0x10]
	adds	x3,x3,x7
	adcs	x4,x4,x8
	adcs	x5,x5,x9
	adcs	x6,x6,x10
	adc	x15,xzr,xzr
	mov	x11,x3
	mov	x12,x4
	mov	x13,x5
	mov	x14,x6
	/* Sub polynomial */
	adr	x2,$mod
	ldp	x7,x8,[x2]
	ldp	x9,x10,[x2,#0x10]
	subs	x11,x11,x7
	sbcs	x12,x12,x8
	sbcs	x13,x13,x9
	sbcs	x14,x14,x10
	sbcs	x15,x15,xzr
	csel	x3,x3,x11,cc
	csel	x4,x4,x12,cc
	csel	x5,x5,x13,cc
	csel	x6,x6,x14,cc
	/* Store results */
	stp	x3,x4,[x0]
	stp	x5,x6,[x0,#0x10]
___
}
sub bn_mod_sub() {
	my $mod = shift;
$code.=<<___;
	/* Load inputs */
	ldp	x3,x4,[x1]
	ldp	x5,x6,[x1,#0x10]
	/* Addition */
	ldp	x7,x8,[x2]
	ldp	x9,x10,[x2,#0x10]
	subs	x3,x3,x7
	sbcs	x4,x4,x8
	sbcs	x5,x5,x9
	sbcs	x6,x6,x10
	sbc	x15,xzr,xzr
	mov	x11,x3
	mov	x12,x4
	mov	x13,x5
	mov	x14,x6
	/* Add polynomial */
	adr	x2,$mod
	ldp	x7,x8,[x2]
	ldp	x9,x10,[x2,#0x10]
	adds	x11,x11,x7
	adcs	x12,x12,x8
	adcs	x13,x13,x9
	adcs	x14,x14,x10
	tst	x15,x15
	csel	x3,x3,x11,eq
	csel	x4,x4,x12,eq
	csel	x5,x5,x13,eq
	csel	x6,x6,x14,eq
	/* Store results */
	stp	x3,x4,[x0]
	stp	x5,x6,[x0,#0x10]
___
}

{
my ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7)=map("x$_",(7..14));

$code.=<<___;
#include "arm_arch.h"
.arch  armv8-a
.text

.align	5
// The polynomial
.Lpoly:
.quad	0xffffffffffffffff,0xffffffff00000000,0xffffffffffffffff,0xfffffffeffffffff
// The order of polynomial
.Lord:
.quad	0x53bbf40939d54123,0x7203df6b21c6052b,0xffffffffffffffff,0xfffffffeffffffff


// void bn_rshift1(BN_ULONG *a);
.globl	bn_rshift1
.type	bn_rshift1,%function
.align  5
bn_rshift1:
	# Load inputs
	ldp x9,x10,[x0]
	ldp x11,x12,[x0,#16]

	# Right shift
	extr x9,x10,x9,#1
	extr x10,x11,x10,#1
	extr x11,x12,x11,#1
	lsr  x12,x12,#1

	# Store results
	stp x9,x10,[x0]
	stp x11,x12,[x0,#16]

	ret
	.size bn_rshift1,.-bn_rshift1

// void ecp_sm2p256_div_by_2(BN_ULONG *r,const BN_ULONG *a);
.globl	ecp_sm2p256_div_by_2
.type	ecp_sm2p256_div_by_2,%function
.align  5
ecp_sm2p256_div_by_2:
	eor x13,x13,x13
	eor x15,x15,x15

	# Load inputs
	ldp x9,x10,[x1]
	ldp x11,x12,[x1,#16]

	mov x14,x9

	# Add polynomial
	ldr x2,.Lpoly
	ldr x3,.Lpoly+8
	ldr x4,.Lpoly+16
	ldr x5,.Lpoly+24
	adds x9,x9,x2
	adcs x10,x10,x3
	adcs x11,x11,x4
	adcs x12,x12,x5
	adcs x13,x13,xzr

	# Parity check
	tst x14,#1
	b.ne .not_equal_1
	ldp x9,x10,[x1]
	ldp x11,x12,[x1,#16]
	mov x13,x15

.not_equal_1:
	extr x9,x10,x9,#1
	extr x10,x11,x10,#1
	extr x11,x12,x11,#1
	extr x12,x13,x12,#1

	# Store results
	stp x9,x10,[x0]
	stp x11,x12,[x0,#16]

	ret
.size ecp_sm2p256_div_by_2,.-ecp_sm2p256_div_by_2

// void ecp_sm2p256_mul_by_3(BN_ULONG *r,const BN_ULONG *a);
.globl	ecp_sm2p256_mul_by_3
.type	ecp_sm2p256_mul_by_3,%function
.align 5
ecp_sm2p256_mul_by_3:
	# Load inputs
	ldp x3,x4,[x1]
	ldp x5,x6,[x1,#16]

	# 2*a
	adds x3,x3,x3
	adcs x4,x4,x4
	adcs x5,x5,x5
	adcs x6,x6,x6
	adcs x7,xzr,xzr

	mov x8,x3
	mov x9,x4
	mov x10,x5
	mov x11,x6

	# Sub polynomial
	adr x2,.Lpoly
	ldp x12,x13,[x2]
	ldp x14,x15,[x2,#16]
	subs x3,x3,x12
	sbcs x4,x4,x13
	sbcs x5,x5,x14
	sbcs x6,x6,x15
	sbcs x7,x7,xzr

	csel x3,x3,x8,cs
	csel x4,x4,x9,cs
	csel x5,x5,x10,cs
	csel x6,x6,x11,cs
	eor x7,x7,x7

	# 3*a
	ldp x12,x13,[x1]
	ldp x14,x15,[x1,#16]
	adds x3,x3,x12
	adcs x4,x4,x13
	adcs x5,x5,x14
	adcs x6,x6,x15
	adcs x7,xzr,xzr

	mov x8,x3
	mov x9,x4
	mov x10,x5
	mov x11,x6

	# Sub polynomial
	adr x2,.Lpoly
	ldp x12,x13,[x2]
	ldp x14,x15,[x2,#16]
	subs x3,x3,x12
	sbcs x4,x4,x13
	sbcs x5,x5,x14
	sbcs x6,x6,x15
	sbcs x7,x7,xzr

	csel x3,x3,x8,cs
	csel x4,x4,x9,cs
	csel x5,x5,x10,cs
	csel x6,x6,x11,cs

	# Store results
	stp x3,x4,[x0]
	stp x5,x6,[x0,#16]

	ret
.size ecp_sm2p256_mul_by_3,.-ecp_sm2p256_mul_by_3

// void ecp_sm2p256_add(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_add
.type	ecp_sm2p256_add,%function
.align	5
ecp_sm2p256_add:
___
	&bn_mod_add(".Lpoly");
$code.=<<___;
	ret
.size ecp_sm2p256_add,.-ecp_sm2p256_add

// void ecp_sm2p256_sub(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_sub
.type	ecp_sm2p256_sub,%function
.align	5
ecp_sm2p256_sub:
___
	&bn_mod_sub(".Lpoly");
$code.=<<___;
	ret
.size ecp_sm2p256_sub,.-ecp_sm2p256_sub

// void ecp_sm2p256_add_mod_ord(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_add_mod_ord
.type	ecp_sm2p256_add_mod_ord,%function
.align	5
ecp_sm2p256_add_mod_ord:
___
	&bn_mod_add(".Lord");
$code.=<<___;
	ret
.size ecp_sm2p256_add_mod_ord,.-ecp_sm2p256_add_mod_ord


// void ecp_sm2p256_sub_mod_ord(BN_ULONG *r,const BN_ULONG *a,const BN_ULONG *b);
.globl	ecp_sm2p256_sub_mod_ord
.type	ecp_sm2p256_sub_mod_ord,%function
.align	5
ecp_sm2p256_sub_mod_ord:
___
	&bn_mod_sub(".Lord");
$code.=<<___;
	ret
.size ecp_sm2p256_sub_mod_ord,.-ecp_sm2p256_sub_mod_ord

.macro RDC
	# r = a mod p256
	# a = a15 | a14 | ... | a0, where ai are 32-bit quantities
	# | a7  | a6  | a5  | a4  | a3  | a2  | a1  | a0  | (+)
	# | a8  | a11 | a10 | a9  | a8  |   0 | a9  | a8  | (+)
	# | a9  | a14 | a13 | a12 | a11 |   0 | a10 | a9  | (+)
	# | a10 | a15 | a14 | a13 | a12 |   0 | a11 | a10 | (+)
	# | a11 |   0 | a15 | a14 | a13 |   0 | a12 | a11 | (+)
	# | a12 |   0 | a15 | a14 | a13 |   0 | a13 | a12 | (+)
	# | a12 |   0 |   0 | a15 | a14 |   0 | a14 | a13 | (+)
	# | a13 |   0 |   0 |   0 | a15 |   0 | a14 | a13 | (+)
	# | a13 |   0 |   0 |   0 |   0 |   0 | a15 | a14 | (+)
	# | a14 |   0 |   0 |   0 |   0 |   0 | a15 | a14 | (+)
	# | a14 |   0 |   0 |   0 |   0 |   0 |   0 | a15 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 | a15 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	# | a15 |   0 |   0 |   0 |   0 |   0 |   0 |   0 | (+)
	# |   0 |   0 |   0 |   0 |   0 | a8  |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a9  |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a13 |   0 |   0 | (-)
	# |   0 |   0 |   0 |   0 |   0 | a14 |   0 |   0 | (-)
	# | U[7]| U[6]| U[5]| U[4]| U[3]| U[2]| U[1]| U[0]|
	# |	V[3]   |	V[2]   |   V[1]	|	V[0]   |
	# until r < p256
	# $s7 (a15|a14),$s6 (a13|a12),$s5 (a11|a10),$s4 (a9|a8)
	# $s3 (a7|a6),$s2 (a5|a4),$s1 (a3|a2),$s0 (a1|a0)

	# 1. 64-bit addition
	eor x3,x3,x3		 // to store all carry
	eor x4,x4,x4
	mov x5,$s6					// rcx <- $s6
	mov x6,$s4					// rdx <- $s4
	# a13 | a12
	adds x5,x5,$s7						// rcx <- $s6 + $s7
	adcs x4,xzr,xzr	// rax <- carry($s6+$s7)
	adds x5,x5,$s7						// rcx <- $s6 + 2*$s7
	adcs x4,x4,xzr
	# a9 | a8
	mov x15,x4					// rbx <- carry (rax)
	adds x6,x6,x5		// rdx <- $s4 + $s6 + 2*$s7
	adcs x15,x15,xzr
	adds x6,x6,$s5						// rdx <- $s4 + $s5 + $s6 + 2*$s7
	adcs x15,x15,xzr
	# sum
	adds $s0,$s0,x6			// $s0 <- $s0 + $s4 + $s5 + $s6 + 2*$s7
	adcs $s1,$s1,x15	 // $s1 <- $s1 + rbx + carry
	adcs $s2,$s2,x5			// $s2 <- $s2 + $s6 + 2*$s7 + carry
	adcs $s3,$s3,$s7
	adcs x3,xzr,xzr
	# add carry
	adds $s3,$s3,x4
	adcs x3,x3,xzr				// all carry

	stp $s0,$s1,[sp,#32]
	stp $s2,$s3,[sp,#48]
	# 2. 4 -> 8  64-bit to 32-bit spread
	mov x4,#0xffffffff
	mov $s0,$s4
	mov $s1,$s5
	mov $s2,$s6
	mov $s3,$s7
	and $s0,$s0,x4				// a8
	and $s1,$s1,x4				// a10
	and $s2,$s2,x4				// a12
	and $s3,$s3,x4				// a14
	lsr $s4,$s4,#32	// a9
	lsr $s5,$s5,#32	// a11
	lsr $s6,$s6,#32	// a13
	lsr $s7,$s7,#32	// a15
	# 3. 32-bit addition
	mov x4,$s3
	add x4,x4,$s2		 // rax <- a12 + a14
	mov x15,$s3
	add	 x15,x15,$s1   // rbx <- a10 + a14
	mov x5,$s7
	add x5,x5,$s6		 // rcx <- a13 + a15
	mov x6,$s0
	add x6,x6,$s4		 // rdx <- a8 + a9
	add $s7,$s7,$s5	// $s7 <-  a11 + a15
	mov $s2,x5			// $s2 <- a13 + a15
	add $s2,$s2,x4				// $s2 <- a12 + a13 + a14 + a15
	add $s1,$s1,$s2	// $s1 <- a10 + a12 + a13 + a14 + a15
	add $s1,$s1,$s2	// $s1 <- a10 + 2*(a12 + a13 + a14 + a15)
	add $s1,$s1,x6				// $s1 <- a8 + a9 + a10 + 2*(a12 + a13 + a14 + a15)
	add $s1,$s1,$s5	// $s1 <- a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	add $s2,$s2,$s6	// $s2 <- a12 + 2*a13 + a14 + a15
	add $s2,$s2,$s5	// $s2 <- a11 + a12 + 2*a13 + a14 + a15
	add $s2,$s2,$s0	// $s2 <- a8 + a11 + a12 + 2*a13 + a14 + a15
	add x6,x6,$s3		 // rdx <- a8 + a9 + a14
	add x6,x6,$s6		 // rdx <- a8 + a9 + a13 + a14
	add $s4,$s4,x5				// $s4 <- a9 + a13 + a15
	add $s5,$s5,$s4	// $s5 <- a9 + a11 + a13 + a15
	add $s5,$s5,x5				// $s5 <- a9 + a11 + 2*(a13 + a15)
	add x4,x4,x15		 // rax <- a10 + a12 + 2*a14

	# U[0]  $s5	a9 + a11 + 2*(a13 + a15)
	# U[1]  %rax	a10 + a12 + 2*a14
	# U[2]
	# U[3]  $s2	a8 + a11 + a12 + 2*a13 + a14 + a15
	# U[4]  $s4	a9 + a13 + a15
	# U[5]  %rbx	a10 + a14
	# U[6]  $s7	a11 + a15
	# U[7]  $s1	a8 + a9 + a10 + a11 + 2*(a12 + a13 + a14 + a15)
	# sub   %rdx	a8 + a9 + a13 + a14

	# $s0 $s3 $s6  %rcx

	# 4. 8 -> 4  32-bit to 64-bit
	# sub %rdx
	mov $s0,x4
	lsl $s0,$s0,#32
	extr x4,$s2,x4,#32
	extr $s2,x15,$s2,#32
	extr x15,$s1,x15,#32
	lsr $s1,$s1,#32

	# 5. 64-bit addition
	adds $s5,$s5,$s0
	adcs x4,x4,xzr
	adcs $s4,$s4,$s2
	adcs $s7,$s7,x15
	adcs x3,x3,$s1

	# V[0] $s5
	# V[1] %rax
	# V[2] $s4
	# V[3] $s7
	# carry %rsi
	# sub %rdx

	# 5. ADD & SUB
	ldp $s0,$s1,[sp,#32]
	ldp $s2,$s3,[sp,#48]

	# ADD
	adds $s0,$s0,$s5
	adcs $s1,$s1,x4
	adcs $s2,$s2,$s4
	adcs $s3,$s3,$s7
	adcs x3,x3,xzr
	# SUB
	subs $s1,$s1,x6
	sbcs $s2,$s2,xzr
	sbcs $s3,$s3,xzr
	sbcs x3,x3,xzr

	# 6. MOD
	# First Mod
	mov x4,x3
	lsl x4,x4,#32
	mov x5,x4
	subs x4,x4,x3

	adds $s0,$s0,x3
	adcs $s1,$s1,x4
	adcs $s2,$s2,xzr
	adcs $s3,$s3,x5

	# Last Mod
	# return y - p if y > p else y
	mov $s4,$s0
	mov $s5,$s1
	mov $s6,$s2
	mov $s7,$s3

	adr x3,.Lpoly
	ldp x4,x15,[x3]
	ldp x16,x17,[x3,#16]

	eor x5,x5,x5
	adcs x5,xzr,xzr

	subs $s0,$s0,x4
	sbcs $s1,$s1,x15
	sbcs $s2,$s2,x16
	sbcs $s3,$s3,x17
	sbcs x5,x5,xzr

	csel $s0,$s0,$s4,cs
	csel $s1,$s1,$s5,cs
	csel $s2,$s2,$s6,cs
	csel $s3,$s3,$s7,cs

	stp $s0,$s1,[x0]
	stp $s2,$s3,[x0,#16]
.endm
___
}

{
my ($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7)=map("x$_",(7..14));
my ($t0,$t1,$t2,$t3)=map("x$_",(3..6));
my ($t4,$t5,$t6,$t7,$t8)=map("x$_",(15..19));

$code.=<<___;
// void ecp_sm2p256_mul(BN_ULONG *r, const BN_ULONG *a, const BN_ULONG *b);
.globl	ecp_sm2p256_mul
.type	ecp_sm2p256_mul,%function
.align 5
ecp_sm2p256_mul:
	# Store scalar registers
	stp	 x29,x30,[sp,#-80]!
	add	 x29,sp,#0
	stp	 x16,x17,[sp,#16]
	stp	 x18,x19,[sp,#64]

	# Load inputs
	ldp $s0,$s1,[x1]
	ldp $s2,$s3,[x1,#16]
	ldp $s4,$s5,[x2]
	ldp $s6,$s7,[x2,#16]

### multiplication ###
	# ========================
	#             s3 s2 s1 s0
	# *           s7 s6 s5 s4
	# ------------------------
	# +           s0 s0 s0 s0
	#              *  *  *  *
	#             s7 s6 s5 s4
	#          s1 s1 s1 s1
	#           *  *  *  *
	#          s7 s6 s5 s4
	#       s2 s2 s2 s2
	#        *  *  *  *
	#       s7 s6 s5 s4
	#    s3 s3 s3 s3
	#     *  *  *  *
	#    s7 s6 s5 s4
	# ------------------------
	# s7 s6 s5 s4 s3 s2 s1 s0
	# ========================

### s0*s4 ###
	mul $t5,$s0,$s4
	umulh $t2,$s0,$s4

### s1*s4 + s0*s5 ###
	mul $t0,$s1,$s4
	umulh $t1,$s1,$s4
	adds $t2,$t2,$t0
	adcs $t3,$t1,xzr

	mul $t0,$s0,$s5
	umulh $t1,$s0,$s5
	adds $t2,$t2,$t0
	adcs $t3,$t3,$t1
	adcs $t4,xzr,xzr

### s2*s4 + s1*s5 + s0*s6 ###
	mul $t0,$s2,$s4
	umulh $t1,$s2,$s4
	adds $t3,$t3,$t0
	adcs $t4,$t4,$t1

	mul $t0,$s1,$s5
	umulh $t1,$s1,$s5
	adds $t3,$t3,$t0
	adcs $t4,$t4,$t1
	adcs $t6,xzr,xzr

	mul $t0,$s0,$s6
	umulh $t1,$s0,$s6
	adds $t3,$t3,$t0
	adcs $t4,$t4,$t1
	adcs $t6,$t6,xzr

### s3*s4 + s2*s5 + s1*s6 + s0*s7 ###
	mul $t0,$s3,$s4
	umulh $t1,$s3,$s4
	adds $t4,$t4,$t0
	adcs $t6,$t6,$t1
	adcs $t7,xzr,xzr

	mul $t0,$s2,$s5
	umulh $t1,$s2,$s5
	adds $t4,$t4,$t0
	adcs $t6,$t6,$t1
	adcs $t7,$t7,xzr

	mul $t0,$s1,$s6
	umulh $t1,$s1,$s6
	adds $t4,$t4,$t0
	adcs $t6,$t6,$t1
	adcs $t7,$t7,xzr

	mul $t0,$s0,$s7
	umulh $t1,$s0,$s7
	adds $t4,$t4,$t0
	adcs $t6,$t6,$t1
	adcs $t7,$t7,xzr

### s3*s5 + s2*s6 + s1*s7 ###
	mul $t0,$s3,$s5
	umulh $t1,$s3,$s5
	adds $t6,$t6,$t0
	adcs $t7,$t7,$t1
	adcs $t8,xzr,xzr

	mul $t0,$s2,$s6
	umulh $t1,$s2,$s6
	adds $t6,$t6,$t0
	adcs $t7,$t7,$t1
	adcs $t8,$t8,xzr

	mul $t0,$s1,$s7
	umulh $t1,$s1,$s7
	adds $s4,$t6,$t0
	adcs $t7,$t7,$t1
	adcs $t8,$t8,xzr

### s3*s6 + s2*s7 ###
	mul $t0,$s3,$s6
	umulh $t1,$s3,$s6
	adds $t7,$t7,$t0
	adcs $t8,$t8,$t1
	adcs $t6,xzr,xzr

	mul $t0,$s2,$s7
	umulh $t1,$s2,$s7
	adds $s5,$t7,$t0
	adcs $t8,$t8,$t1
	adcs $t6,$t6,xzr

### s3*s7 ###
	mul $t0,$s3,$s7
	umulh $t1,$s3,$s7
	adds $s6,$t8,$t0
	adcs $s7,$t6,$t1

	mov $s0,$t5
	mov $s1,$t2
	mov $s2,$t3
	mov $s3,$t4

	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0

### Reduction ###
	RDC

	# Restore scalar registers
	ldp x16,x17,[sp,#16]
	ldp x18,x19,[sp,#64]
	ldp x29,x30,[sp],#80

	ret
.size ecp_sm2p256_mul,.-ecp_sm2p256_mul

// void ecp_sm2p256_sqr(BN_ULONG *r, const BN_ULONG *a);
.globl ecp_sm2p256_sqr
.type ecp_sm2p256_sqr,%function
.align	5

ecp_sm2p256_sqr:
	# Store scalar registers
	stp	 x29,x30,[sp,#-80]!
	add	 x29,sp,#0
	stp	 x16,x17,[sp,#16]
	stp	 x18,x19,[sp,#64]

	# Load inputs
	ldp $s4,$s5,[x1]
	ldp $s6,$s7,[x1,#16]

### square ###
	# ========================
	#             s7 s6 s5 s4
	# *           s7 s6 s5 s4
	# ------------------------
	# +           s4 s4 s4 s4
	#              *  *  *  *
	#             s7 s6 s5 s4
	#          s5 s5 s5 s5
	#           *  *  *  *
	#          s7 s6 s5 s4
	#       s6 s6 s6 s6
	#        *  *  *  *
	#       s7 s6 s5 s4
	#    s7 s7 s7 s7
	#     *  *  *  *
	#    s7 s6 s5 s4
	# ------------------------
	# s7 s6 s5 s4 s3 s2 s1 s0
	# ========================

### s4*s5 ###
	mul $s1,$s4,$s5
	umulh $s2,$s4,$s5

### s4*s6 ###
	mul $t0,$s6,$s4
	umulh $s3,$s6,$s4
	adds $s2,$s2,$t0
	adcs $s3,$s3,xzr

### s4*s7 + s5*s6 ###
	mul $t0,$s7,$s4
	umulh $t1,$s7,$s4
	adds $s3,$s3,$t0
	adcs $s0,$t1,xzr

	mul $t0,$s6,$s5
	umulh $t1,$s6,$s5
	adds $s3,$s3,$t0
	adcs $s0,$s0,$t1
	adcs $t2,xzr,xzr

### s5*s7 ###
	mul $t0,$s7,$s5
	umulh $t1,$s7,$s5
	adds $s0,$s0,$t0
	adcs $t2,$t2,$t1

### s6*s7 ###
	mul $t0,$s7,$s6
	umulh $t1,$s7,$s6
	adds $t2,$t2,$t0
	adcs $t3,$t1,xzr

### 2*(t3,t2,s0,s3,s2,s1) ###
	adds $s1,$s1,$s1
	adcs $s2,$s2,$s2
	adcs $s3,$s3,$s3
	adcs $s0,$s0,$s0
	adcs $t2,$t2,$t2
	adcs $t3,$t3,$t3
	adcs $t4,xzr,xzr

### s4*s4 ###
	mul $t5,$s4,$s4
	umulh $t6,$s4,$s4

### s5*s5 ###
	mul $s4,$s5,$s5
	umulh $s5,$s5,$s5

### s6*s6 ###
	mul $t0,$s6,$s6
	umulh $t1,$s6,$s6

### s7*s7 ###
	mul $t7,$s7,$s7
	umulh $t8,$s7,$s7

	adds $s1,$s1,$t6
	adcs $s2,$s2,$s4
	adcs $s3,$s3,$s5
	adcs $s0,$s0,$t0
	adcs $t2,$t2,$t1
	adcs $t3,$t3,$t7
	adcs $t4,$t4,$t8

	mov $s4,$s0
	mov $s0,$t5
	mov $s5,$t2
	mov $s6,$t3
	mov $s7,$t4

	# result of mul: s7 s6 s5 s4 s3 s2 s1 s0

### Reduction ###
	RDC

	# Restore scalar registers
	ldp x16,x17,[sp,#16]
	ldp x18,x19,[sp,#64]
	ldp x29,x30,[sp],#80

	ret
.size ecp_sm2p256_sqr,.-ecp_sm2p256_sqr

___


}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	print $_,"\n";
}
close STDOUT or die "error closing STDOUT: $!";		# enforce flush
