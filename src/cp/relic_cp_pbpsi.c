/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (c) 2021 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or modify it under the
 * terms of the version 2.1 (or later) of the GNU Lesser General Public License
 * as published by the Free Software Foundation; or version 2.0 of the Apache
 * License as published by the Apache Software Foundation. See the LICENSE files
 * for more details.
 *
 * RELIC is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the LICENSE files for more details.
 *
 * You should have received a copy of the GNU Lesser General Public or the
 * Apache License along with RELIC. If not, see <https://www.gnu.org/licenses/>
 * or <https://www.apache.org/licenses/>.
 */

/**
 * @file
 *
 * Implementation of pairing-based laconic private set intersection protocols.
 *
 * @ingroup cp
 */

#include "relic.h"

/*============================================================================*/
/* Public definitions                                                         */
/*============================================================================*/


int cp_pbpsi_ask(g1_t *d,  const bn_t *x, bn_t *b, size_t m) {
	int i, result = RLC_OK;
	/*bn_t t,r, s,q,res, _x[m];

	bn_null(q);
	bn_null(t);
	bn_null(s);
	bn_null(r);
	bn_null(res);

	RLC_TRY {
		bn_new(q);
		bn_new(t);
		bn_new(s);
		bn_new(r);
		bn_new(res);

		for (i = 0; i < m; i++) {
			bn_null(_x[i]);
			bn_new(_x[i]);
		}

		pc_get_ord(q);
		bn_rand_mod(r, q);
		bn_rand_mod(s, q);
		if (m == 0) {
			g1_mul_gen(d[0], r);
			g1_mul(d[1],d[0],s);
		} else {
			bn_add(_x[0],s,x[0]);
			bn_mod(res,_x[0],q);
			for(i=1;i<m;i++){
				bn_add(_x[i],s,x[i]);
				bn_mul(res,res,_x[i]);
				bn_mod(res,res,q);
			}
			bn_div(res,r,res);
			g1_mul_gen(d[0],res);
			g1_mul(d[1],d[0],s);
			for (i = 0; i < m; i++) {
				bn_mul(b[i],res,_x[i]);
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(t);
		for (i = 0; i <= m; i++) {
			bn_free(_x[i]);
		}
		RLC_FREE(_x);
	}*/
	return result;
}

int cp_pbpsi_ans(g1_t *t, g1_t *u, g1_t *d, const bn_t *y, size_t n) {
	int j, result = RLC_OK;
	bn_t q, tj;
	uint_t *shuffle = RLC_ALLOCA(uint_t, n);

	bn_null(q);
	bn_null(tj);

	RLC_TRY {
		bn_new(q);
		bn_new(tj);
		if (shuffle == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}

		util_perm(shuffle, n);
		pc_get_ord(q);
		for (j = 0; j < n; j++) {
			bn_rand_mod(tj, q);
			g1_mul(t[j],d[0], y[shuffle[j]]);
			g1_add(t[j],d[1],t[j]);
			g1_mul(t[j],t[j],tj);
			g1_mul_gen(u[j], tj);
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
		bn_free(q);
		bn_free(tj);
		RLC_FREE(shuffle);
	}
	return result;
}

int cp_pbpsi_int(bn_t *z,size_t len, const bn_t *b, const bn_t *x,size_t m, const g1_t *t, const g1_t *u, size_t n) {
	int j, k, result = RLC_OK;
g1_t g;
g1_null(g);
g1_new(g);
	RLC_TRY {

		len = 0;
		if (m > 0) {
			for (k = 0; k < m; k++) {
				for (j = 0; j < n; j++) {
					g1_mul(g,u[k],b[j]);
					if (g1_cmp(g, t[k]) == RLC_EQ ) {
						bn_copy(z[len], x[k]);
						len++;
					}
				}
			}
		}
	}
	RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {
	}
	return result;
}
