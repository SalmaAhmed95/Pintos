//
// Created by karfass on 02/12/17.
//

#include "fixedpoint.h"
#include "stdint.h"

#define F 16384 // 2^14

/* converts the integer n to fixed point representation */
real convert_to_fixed(int n) {
    return n * F;
}

/* converts fixed point to integer rounded towards zero */
int convert_to_integer_zeroround(real x) {
    return x / F;
}

/* converts fixed point to integer rounded towards the nearest */
int convert_to_integer_nearestround(real x) {
    if (x >= 0)
        return (x + F / 2) / F;
    else
        return (x - F / 2) / F;
}

/* adds two fixed point numbers x and y */
real add_fixed(real x, real y) {
    return x + y;
}

/* adds a fixed point number x to an integer n */
real add_int(real x, int n) {
    return x + n * F;
}

/* subtracts two fixed point numbers x and y */
real subtract_fixed(real x, real y) {
    return x - y;
}

/* subtracts an integer n from a fixed point number x */
real subtract_int(real x, int n) {
    return x - n * F;
}

/* multiplies two fixed point numbers x and y */
real multiply_fixed(real x, real y) {
    return ((int64_t) x) * y / F;
}

/* multiplies a fixed point number x with an integer n */
real multiply_int(real x, int n) {
    return x * n;
}

/* divides a fixed point number x by another fixed point number y */
real divide_fixed(real x, real y) {
    return ((int64_t) x) * F / y;
}

/* divides a fixed point number x by an integer n */
real divide_int(real x, int n) {
    return x / n;
}