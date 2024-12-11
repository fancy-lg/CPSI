@misc{relic-toolkit,
    author = {D. F. Aranha and C. P. L. Gouvêa and T. Markmann and R. S. Wahby and K. Liao},        
    title = {{RELIC is an Efficient LIbrary for Cryptography}},
    howpublished = {\url{https://github.com/relic-toolkit/relic}},
}
#include <stdio.h>
#include <assert.h>

#include "relic.h"
#include "relic_test.h"

int cp_common_receiver(g1_t r,bn_t a){
	g1_mul_gen(r,a);
}
int cp_pbpsi_common_receiver(g1_t r,g2_t *b2,g1_t *b3,g1_t *d,bn_t *x,size_t m,bn_t *_x){	
	int i, result = RLC_OK;
	bn_t s,q,res,a,c1,c2;
	g1_t g1,g2;
	bn_null(s);
	bn_null(q);
	bn_null(c1);
	bn_null(c2);
	bn_null(a);
	bn_null(res);
	for(i=0;i<m;i++){
		bn_null(_x[i]);
	}
	RLC_TRY{
		bn_new(s);
		bn_new(q);
		bn_new(c1);
		bn_new(c2);
		bn_new(a);
		bn_new(res);
		for(i=0;i<m;i++){
		bn_new(_x[i]);
	}
		pc_get_ord(q);
	    bn_rand_mod(a,q);
		bn_rand_mod(s,q);
		for(i=0;i<m;i++){
			bn_add(_x[i],s,x[i]);
			bn_mod(_x[i],_x[i],q);
			bn_mul(_x[i],a,_x[i]);
			bn_mod(_x[i],_x[i],q);
			g2_mul_gen(b2[i],_x[i]);
			bn_mod_inv(res,_x[i],q);
			g1_mul(b3[i],r,res);
		}
		bn_mod_inv(c1,a,q);
		g1_mul(d[0],r,c1);
		g1_mul_gen(d[1],s);
	}RLC_CATCH_ANY {
		result = RLC_ERR;
	}
	RLC_FINALLY {}
	return result;
}
int cp_pbpsi_second(g1_t *t, g1_t *u, g1_t *d, const bn_t *y, size_t n) {
	int j, result = RLC_OK;
	bn_t q, tj,res;
	uint_t *shuffle = RLC_ALLOCA(uint_t, n);

	bn_null(q);
	bn_null(tj);
	bn_null(res);

	RLC_TRY {
		bn_new(q);
		bn_new(tj);
		bn_new(res);
		if (shuffle == NULL) {
			RLC_THROW(ERR_NO_MEMORY);
		}
		util_perm(shuffle, n);
		pc_get_ord(q);
		for (j = 0; j < n; j++) {
			bn_rand_mod(tj, q);
			bn_add(res,tj,y[shuffle[j]]);
			bn_mod_inv(res,res,q);
			g1_mul_gen(t[j],tj);
			g1_sub(t[j],d[1],t[j]);
			g1_mul(t[j],t[j],res);
			g1_mul(u[j],d[0],res);
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

int cp_pbpsi_intersection(int len,bn_t a, const g2_t *b2, const g1_t *b3,size_t m, const g1_t *t, const g1_t *u, size_t n,g1_t *g3,g1_t *g4) {
	int j, k,num[m],result = RLC_OK;
	gt_t e1,e2;
	g1_t g1;
	g2_t g2;
	bn_t q,res;
	gt_null(e1);
	gt_new(e1);
	gt_null(e2);
	gt_new(e2);
	g1_null(g1);
	g1_new(g1);
	g2_null(g2);
	g2_new(g2);
	bn_null(q);
	bn_new(q);
	bn_null(res);
	bn_new(res);
	pc_get_ord(q);
	g2_mul_gen(g2,a);
	for(j=0;j<m;j++){
		num[j]=0;
	}
		RLC_TRY {
			if (m > 0) {
				len = 0;
				for (k = 0; k < n; k++) {
					pc_map(e1,t[k],g2);
					for (j = 0; j < m; j++) {
						g1_sub(g1,u[k],b3[j]);
						pc_map(e2,g1,b2[j]);
						if (gt_cmp(e1,e2) == RLC_EQ ) {
							num[j]=1;
							len++;
						}
					}
				}
				g1_mul_gen(g1,a);
				k=0;
				for(j=0;j<len;j++){
					if(num[j]==1){
						bn_rand_mod(res,q);
						g1_mul(g4[k],g1,res);
						g1_mul(g3[k],b3[j],res);
						k++;
					}
				}
				for(j=len;j<n;j++){
					bn_rand_mod(res,q);
					g1_mul(g4[k],g1,res);
					bn_rand_mod(res,q);
					g1_mul_gen(g3[k],res);
					k++;
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
int cp_pbpsi_out(bn_t *b1,size_t m,size_t n,g1_t *g3,g1_t *g4,bn_t *x,bn_t *z,bn_t *_x) {
	int i=0;
	for(int j=0;j<m;j++){
		g1_mul(g3[j],g3[j],_x[j]);
		if(g1_cmp(g3[i],g4[i])==RLC_EQ){
			bn_copy(z[i],x[j]);
			i++;
		}
	}
	printf("\n%d\n",i);
}


#undef M
#undef N
#include "params.h"

static void bench(void) {
	int len, result, code = RLC_ERR;
	bn_t q,a,x[M], y[N], b1[M],z[N],random,*_x = RLC_ALLOCA(bn_t, M);;
	g1_t u[N],d[2],t[N],r,b3[M],g3[M],g4[M];
	crt_t crt;
	g2_t b2[M];

	bn_null(q);
	bn_null(a)
	crt_null(crt);
	bn_new(q);
	bn_new(a);
	for (int i = 0; i < M; i++) {
		bn_null(b1[i]);
		g1_null(g3[i]);
		g1_null(g4[i]);
		g1_null(b3[i]);
		g2_null(b2[i]);
		bn_null(x[i]);
		bn_new(b1[i]);
		g1_new(g3[i]);
		g1_new(g4[i]);
		g1_new(b3[i]);
		bn_new(x[i]);
		g2_new(b2[i]);
	}
	g1_null(d[0]);
	g1_new(d[0]);
	g1_null(r);
	g1_new(r);
	g1_null(d[1]);
	g1_new(d[1]);
	for (int i = 0; i < N; i++) {
		bn_null(y[i]);
		bn_null(z[i]);
		g1_null(u[i]);
		g1_null(t[i]);
		bn_new(y[i]);
		bn_new(z[i]);
		g1_new(u[i]);
		g1_new(t[i]);
	}
	crt_new(crt);

	pc_get_ord(q);
	for (int j = 0; j < M; j++) {
		bn_rand_mod(x[j], q);
	}
	for (int j = 0; j < N; j++) {
		bn_rand_mod(y[j], q);
	}

	bn_rand_mod(a,q);
    BENCH_RUN("cp_comment_receiver") {
		BENCH_ADD(cp_common_receiver(r,a));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_common_receiver") {
		BENCH_ADD(cp_pbpsi_common_receiver(r,b2,b3,d, x, M,_x));
	} BENCH_END;
	BENCH_RUN("cp_pbpsi_second") {
		BENCH_ADD(cp_pbpsi_second(t, u,  d, x, N));
	} BENCH_END;

	BENCH_RUN("cp_pbpsi_intersection") {
		BENCH_ADD(cp_pbpsi_intersection(len, a,b2,b3, M, t, u, N,g3,g4));
	} BENCH_END;
	BENCH_RUN("cp_pbpsi_out") {
		BENCH_ADD(cp_pbpsi_out(b1,M,N,g3,g4,x,z,_x));
	} BENCH_END;

    bn_free(q);
	bn_free(r);
	g1_free(ss);
	for (int i = 0; i < M; i++) {
		bn_free(x[i]);
		bn_free(z[i]);
		g2_free(d[i]);
		g2_free(s[i]);
	}
	g2_free(d[M]);
	g2_free(s[M]);
	for (int i = 0; i < N; i++) {
		bn_free(y[i]);
		g1_free(u[i]);
		gt_free(t[i]);
	}
}

int main(int argc, char *argv[]) {
	int m, n;
	core_init();
	if (pc_param_set_any() == RLC_OK) {

		bench();
	}
	core_clean();
}
