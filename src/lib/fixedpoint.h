//
// Created by karfass on 02/12/17.
//

#ifndef PINTOS_FIXEDPOINT_H
#define PINTOS_FIXEDPOINT_H

typedef int real;

/* converts the integer n to fixed point representation */
real convert_to_fixed(int n);

/* converts fixed point to integer rounded towards zero */
int convert_to_integer_zeroround(real x);

/* converts fixed point to integer rounded towards the nearest */
int convert_to_integer_nearestround(real x);

/* adds two fixed point numbers x and y */
real add_fixed(real x, real y);

/* adds a fixed point number x to an integer n */
real add_int(real x, int n);

/* subtracts two fixed point numbers x and y */
real subtract_fixed(real x, real y);

/* subtracts an integer n from a fixed point number x */
real subtract_int(real x, int n);

/* multiplies two fixed point numbers x and y */
real multiply_fixed(real x, real y);

/* multiplies a fixed point number x with an integer n */
real multiply_int(real x, int n);

/* divides a fixed point number x by another fixed point number y */
real divide_fixed(real x, real y);

/* divides a fixed point number x by an integer n */
real divide_int(real x, int n);


#endif //PINTOS_FIXEDPOINT_H