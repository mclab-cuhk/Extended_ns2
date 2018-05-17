/* This is a very naive Reno implementation, shown as an example on how to develop a new congestion control algorithm with TCP-Linux. */
/* This file itself should be copied to tcp/linux/ directory. */
/* To let the compiler compiles this file, an entry "tcp/linux/<NameOfThisFile>.o" should be added to Makefile */

/* This definition lets the compiler knows the name of this protocol */
#define NS_PROTOCOL "tcp_golf.c"

/* This two header files link your implementation to TCP-Linux */

#include "../ns-linux-c.h"
#include "../ns-linux-util.h"


#define TCP_WESTWOOD_RTT_MIN   (HZ/20)	/* 50ms */
#define TCP_WESTWOOD_INIT_RTT  (20*HZ)	/* maybe too conservative?! */


#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */

#define ACK_RATIO_SHIFT	4


/********************************************************************/
/* Two methods of hybrid slow start */
#define HYSTART_ACK_TRAIN	0x1
#define HYSTART_DELAY		0x2

/* Number of delay samples for detecting the increase of delay */
#define HYSTART_MIN_SAMPLES	8
#define HYSTART_DELAY_MIN	(4U<<3)
#define HYSTART_DELAY_MAX	(16U<<3)
//#define HYSTART_DELAY_THRESH(x)		
/********************************************************************/

static int fast_convergence __read_mostly = 1;
static int max_increment __read_mostly = 16;
static int beta __read_mostly = 819;	/* = 819/1024 (BICTCP_BETA_SCALE) */
static int initial_ssthresh __read_mostly;
static int bic_scale __read_mostly = 41;
static int tcp_friendliness __read_mostly = 1;

/********************************************************************/
static int hystart __read_mostly = 1;
static int hystart_detect __read_mostly = HYSTART_ACK_TRAIN | HYSTART_DELAY;
static int hystart_low_window __read_mostly = 16;
static int hystart_ack_delta __read_mostly = 2;
/********************************************************************/

static u32 cube_rtt_scale __read_mostly;
static u32 beta_scale __read_mostly;
static u64 cube_factor __read_mostly;

/* Note parameters that are used for precomputing scale factors are read-only */
module_param(fast_convergence, int, 0644);
MODULE_PARM_DESC(fast_convergence, "turn on/off fast convergence");
module_param(max_increment, int, 0644);
MODULE_PARM_DESC(max_increment, "Limit on increment allowed during binary search");
module_param(beta, int, 0444);
MODULE_PARM_DESC(beta, "beta for multiplicative increase");
module_param(initial_ssthresh, int, 0644);
MODULE_PARM_DESC(initial_ssthresh, "initial value of slow start threshold");
module_param(bic_scale, int, 0444);
MODULE_PARM_DESC(bic_scale, "scale (scaled by 1024) value for bic function (bic_scale/1024)");
module_param(tcp_friendliness, int, 0644);
MODULE_PARM_DESC(tcp_friendliness, "turn on/off tcp friendliness");

/********************************************************************/
module_param(hystart, int, 0644);
MODULE_PARM_DESC(hystart, "turn on/off hybrid slow start algorithm");
module_param(hystart_detect, int, 0644);
MODULE_PARM_DESC(hystart_detect, "hybrid slow start detection mechanisms"
		 " 1: packet-train 2: delay 3: both packet-train and delay");
module_param(hystart_low_window, int, 0644);
MODULE_PARM_DESC(hystart_low_window, "lower bound cwnd for hybrid slow start");
module_param(hystart_ack_delta, int, 0644);
MODULE_PARM_DESC(hystart_ack_delta, "spacing between ack's indicating train (msecs)");
/********************************************************************/


struct cdg_minmax {
	s32 min;
	s32 max;
};

enum cdg_state {
	CDG_UNKNOWN = 0,
	CDG_NONFULL = 1,
	CDG_FULL    = 2,
	CDG_BACKOFF = 3,
};



/* BIC TCP Parameters */
struct golf {
// parameters for cubic
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */
	u32	delay_min;	/* min delay */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */
	
// parameters for hystart
	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
	
// parameters for westwood
	u32	ww_bw_ns_est;       
	u32	ww_bw_est;          
	u32	ww_rtt_win_sx;     
	u32	ww_bk;
	u32	ww_snd_una;         
	u32	ww_cumul_ack;
	u32	ww_rtt;
	u32	ww_rtt_min;       
	u8	ww_first_ack;       
	u8	ww_reset_rtt_min;  
	u32	ww_accounted;

// parameters for CDG
	struct cdg_minmax rtt_interval;
	struct cdg_minmax rtt;
	struct cdg_minmax rtt_prev;
	struct cdg_minmax rtt_all_time;
	u32 rtt_seq;
	u32 rtt_average;
	u32 rtt_count;
	
// deal with deep queue
	u32 last_bw_sample;
	u32 stable_count;
	u32 stable_flag;
};


/********************************************************************/
static inline void bictcp_hystart_reset( u32 ack,u32 end_seq,  struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct golf *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = tcp_time_stamp;
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}
/********************************************************************/


static void golf_init(struct sock *sk)
{

	struct golf *ca = inet_csk_ca(sk);
	struct tcp_sock *tp = tcp_sk(sk);
	ca->cnt = 0;
	ca->last_max_cwnd = 0;
	ca->loss_cwnd = 0;
	ca->last_cwnd = 0;
	ca->last_time = 0;
	ca->bic_origin_point = 0;
	ca->bic_K = 0;
	ca->delay_min = 0;
	ca->epoch_start = 0;
	ca->ack_cnt = 0;
	ca->tcp_cwnd = 0;
	ca->delayed_ack = 2 << ACK_RATIO_SHIFT;

	ca->ww_bw_ns_est = 0;
	ca->ww_bw_est = 0;
	ca->ww_rtt_win_sx = tcp_time_stamp;	
	ca->ww_bk = 0;
	ca->ww_snd_una = tcp_sk(sk)->snd_una;	
	ca->ww_cumul_ack = 0;	
	ca->ww_rtt = 0;
	ca->ww_rtt_min = 0;   
	ca->ww_first_ack = 1;
	ca->ww_reset_rtt_min = 1;
	ca->ww_accounted = 0;	

	ca->sample_cnt = 0;	
	ca->found = 0;		
	ca->round_start = 0;	
	ca->end_seq = 0;
	ca->last_ack = 0;	
	ca->curr_rtt = 0;	

	ca->last_bw_sample = 0;
	ca->stable_count = 0;
	ca->stable_flag = 0;

// parameters for CDG
	ca->rtt_seq = tp->snd_nxt;
	ca->rtt_count = 1;



	if (hystart)
		bictcp_hystart_reset(1, 1, sk);
}



static s32 tcp_cdg_grad(struct golf *ca)
{

	s32 gmin = ca->rtt.min - ca->rtt_prev.min;
	s32 gmax = ca->rtt.max - ca->rtt_prev.max;
	s32 grad;
	
	
	//fprintf(stderr, "cdg_grad: %lu  %lu   %lu  %lu    %lu  %lu    %lu  %lu   %lu        %lu    %lu\n",ca->rtt.min, ca->rtt_prev.min, ca->rtt.max , ca->rtt_prev.max,  gmin, gmax, ca->rtt_interval.min, ca->rtt_interval.max, tcp_time_stamp, ca->rtt_average, ca->rtt_count);	

/*
	if (ca->gradients) {
		ca->gsum.min += gmin - ca->gradients[ca->tail].min;
		ca->gsum.max += gmax - ca->gradients[ca->tail].max;
		ca->gradients[ca->tail].min = gmin;
		ca->gradients[ca->tail].max = gmax;
		ca->tail = (ca->tail + 1) & (window - 1);
		gmin = ca->gsum.min;
		gmax = ca->gsum.max;
	}
*/
}







/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	/*
	 * cbrt(x) MSB values for x MSB values in [0..63].
	 * Precomputed then refined by hand - Willy Tarreau
	 *
	 * For x in [0..63],
	 *   v = cbrt(x << 18) - 1
	 *   cbrt(x) = (v[x] + 10) >> 6
	 */
	static const u8 v[] = {
		/* 0x00 */    0,   54,   54,   54,  118,  118,  118,  118,
		/* 0x08 */  123,  129,  134,  138,  143,  147,  151,  156,
		/* 0x10 */  157,  161,  164,  168,  170,  173,  176,  179,
		/* 0x18 */  181,  185,  187,  190,  192,  194,  197,  199,
		/* 0x20 */  200,  202,  204,  206,  209,  211,  213,  215,
		/* 0x28 */  217,  219,  221,  222,  224,  225,  227,  229,
		/* 0x30 */  231,  232,  234,  236,  237,  239,  240,  242,
		/* 0x38 */  244,  245,  246,  248,  250,  251,  252,  254,
	};

	b = fls64(a);
	if (b < 7) {
		/* a in [0..63] */
		return ((u32)v[(u32)a] + 35) >> 6;
	}

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/*
	 * Newton-Raphson iteration
	 *                         2
	 * x    = ( 2 * x  +  a / x  ) / 3
	 *  k+1          k         k
	 */
	x = (2 * x + (u32)div64_64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);
	return x;
}


/////////////////////////////////////////////////////////////////////

/////////////////////////////////////////////////////////////////////



/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct golf *ca, u32 cwnd)
{
	u64 offs;
	u32 delta, t, bic_target, min_cnt, max_cnt;

	ca->ack_cnt++;	/* count the number of ACKs */

	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;

	ca->last_cwnd = cwnd;
	ca->last_time = tcp_time_stamp;

	if (ca->epoch_start == 0) {
		ca->epoch_start = tcp_time_stamp;	/* record the beginning of an epoch */
		ca->ack_cnt = 1;			/* start counting */
		ca->tcp_cwnd = cwnd;			/* syn with cubic */

		if (ca->last_max_cwnd <= cwnd) {
			ca->bic_K = 0;
			ca->bic_origin_point = cwnd;
		} else {
			/* Compute new K based on
			 * (wmax-cwnd) * (srtt>>3 / HZ) / c * 2^(3*bictcp_HZ)
			 */
			ca->bic_K = cubic_root(cube_factor
					       * (ca->last_max_cwnd - cwnd));
			ca->bic_origin_point = ca->last_max_cwnd;
		}
	}

	/* cubic function - calc*/
	/* calculate c * time^3 / rtt,
	 *  while considering overflow in calculation of time^3
	 * (so time^3 is done by using 64 bit)
	 * and without the support of division of 64bit numbers
	 * (so all divisions are done by using 32 bit)
	 *  also NOTE the unit of those veriables
	 *	  time  = (t - K) / 2^bictcp_HZ
	 *	  c = bic_scale >> 10
	 * rtt  = (srtt >> 3) / HZ
	 * !!! The following code does not have overflow problems,
	 * if the cwnd < 1 million packets !!!
	 */

	/* change the unit from HZ to bictcp_HZ */
	t = ((tcp_time_stamp + (ca->delay_min>>3) - ca->epoch_start)
	     << BICTCP_HZ) / HZ;

	if (t < ca->bic_K)		/* t - K */
		offs = ca->bic_K - t;
	else
		offs = t - ca->bic_K;

	/* c/rtt * (t-K)^3 */
	delta = (cube_rtt_scale * offs * offs * offs) >> (10+3*BICTCP_HZ);
	if (t < ca->bic_K)                                	/* below origin*/
		bic_target = ca->bic_origin_point - delta;
	else                                                	/* above origin*/
		bic_target = ca->bic_origin_point + delta;

	/* cubic function - calc bictcp_cnt*/
	if (bic_target > cwnd) {
		ca->cnt = cwnd / (bic_target - cwnd);
	} else {
		ca->cnt = 100 * cwnd;              /* very small increment*/
	}

	if (ca->delay_min > 0) {
		/* max increment = Smax * rtt / 0.1  */
		min_cnt = (cwnd * HZ * 8)/(10 * max_increment * ca->delay_min);

		/* use concave growth when the target is above the origin */
		if (ca->cnt < min_cnt && t >= ca->bic_K)
			ca->cnt = min_cnt;
	}

	/* slow start and low utilization  */
	if (ca->loss_cwnd == 0)		/* could be aggressive in slow start */
		ca->cnt = 50;

	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;
		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd){	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	ca->cnt = (ca->cnt << ACK_RATIO_SHIFT) / ca->delayed_ack;
	if (ca->cnt == 0)			/* cannot be zero */
		ca->cnt = 1;
}


/* Keep track of minimum rtt */
static inline void measure_delay(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct golf *ca = inet_csk_ca(sk);
	u32 delay;

	/* No time stamp */
	if (!(tp->rx_opt.saw_tstamp && tp->rx_opt.rcv_tsecr) ||
	     /* Discard delay samples right after fast recovery */
	    (s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

	delay = (tcp_time_stamp - tp->rx_opt.rcv_tsecr)<<3;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;
}

static void golf_cong_avoid(struct sock *sk, u32 ack,
			      u32 seq_rtt, u32 in_flight, int data_acked)
{
	u32 acked = data_acked;

	struct tcp_sock *tp = tcp_sk(sk);
	struct golf *ca = inet_csk_ca(sk);

	if (after(ack, ca->rtt_seq) ) {
		s32	grad = tcp_cdg_grad(ca);
		ca->rtt_seq = tp->snd_nxt;
		ca->rtt_prev = ca->rtt;
		ca->last_ack = 0;
		ca->sample_cnt = 0;
	}

//	if (ca->stable_flag){
//		tcp_reno_cong_avoid(sk,ack, seq_rtt, in_flight, data_acked);
//		return;
//	}


	// new "tcp_is_cwnd_limited" implementation.
	if (tp->snd_cwnd < tp->snd_ssthresh){	//in slow start phase
		if (    !tcp_is_cwnd_limited(sk, in_flight * 2)   )
			return;
	}
	else{
		if (    !tcp_is_cwnd_limited(sk, in_flight)   )
			return;
	}

	// check for "tcp_in_slow_start"
	if (tp->snd_cwnd < tp->snd_ssthresh){	
		if (hystart && after(ack, ca->end_seq))
			bictcp_hystart_reset(ack, ca->end_seq, sk);

		/*************************tcp_slow_start**************************/
		u32 cwnd = min(tp->snd_cwnd + acked, tp->snd_ssthresh);
		acked -= cwnd - tp->snd_cwnd;
		tp->snd_cwnd = min(cwnd, tp->snd_cwnd_clamp);
		/*************************tcp_slow_start**************************/
	}

	if (acked){
		bictcp_update(ca, tp->snd_cwnd);

		/*************************tcp_cong_avoid_ai**************************/
		if (tp->snd_cwnd_cnt >= ca->cnt) {		// this one is less precise
			tp->snd_cwnd_cnt = 0;
			tp->snd_cwnd++;
		}

		tp->snd_cwnd_cnt += acked;			// this one is more precise
		if (tp->snd_cwnd_cnt >= ca->cnt) {
			u32 delta = tp->snd_cwnd_cnt / ca->cnt;

			tp->snd_cwnd_cnt -= delta * ca->cnt;
			tp->snd_cwnd += delta;
		}
		tp->snd_cwnd = min(tp->snd_cwnd, tp->snd_cwnd_clamp);	
		/*************************tcp_cong_avoid_ai**************************/
		}
}

static u32 golf_recalc_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct golf *ca = inet_csk_ca(sk);
	ca->epoch_start = 0;	/* end of epoch */

	ca->stable_flag = 0;
	ca->stable_count = 0;

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 golf_undo_cwnd(struct sock *sk)
{
	//struct golf *ca = inet_csk_ca(sk);
	struct golf *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->last_max_cwnd);
}

static void golf_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		golf_init(inet_csk_ca(sk));
}




/********************************************************************/

static void hystart_update(struct sock *sk, u32 delay)
{
	//fprintf(		stderr, "hystart_update000  %d\n", delay>>3);		

	struct tcp_sock *tp = tcp_sk(sk);
	struct golf *ca = inet_csk_ca(sk);

	if (ca->found & hystart_detect)
		return;

	if (hystart_detect & HYSTART_ACK_TRAIN) {
		u32 now = tcp_time_stamp; //bictcp_clock();

		/* first detection parameter - ack-train detection */
		if ((s32)(now - ca->last_ack) <= hystart_ack_delta) {
			ca->last_ack = now;
			
			if ((s32)((now - ca->round_start)) > (ca->delay_min >>4)) {
				ca->found |= HYSTART_ACK_TRAIN;

				tp->snd_ssthresh = tp->snd_cwnd;
				fprintf(stderr, "		hystart_update111  %d   %d  %d    %d\n", ca->cnt, tp->snd_ssthresh, (now - ca->round_start),(ca->delay_min >>3)>>1);	
			}
		}
	}

/*
	if (hystart_detect & HYSTART_DELAY ) {
		// obtain the minimum delay of more than sampling packets 
		if (ca->sample_cnt < HYSTART_MIN_SAMPLES) {
			if (ca->curr_rtt == 0 || ca->curr_rtt > (delay>>3))
				ca->curr_rtt = (delay>>3);
			ca->sample_cnt++;

		} else {
			u64 H = (ca->delay_min >> 3)>>3;
			if (H > HYSTART_DELAY_MAX)
				H = HYSTART_DELAY_MAX;
			if (H < HYSTART_DELAY_MIN)
				H = HYSTART_DELAY_MIN;
			if (ca->curr_rtt > (ca->delay_min >>3) + H) {
				ca->found |= HYSTART_DELAY;

				tp->snd_ssthresh = tp->snd_cwnd;
				
				fprintf(stderr, "		hystart_update333  %d     %d    %d   %d  %d     %d    %d\n", (ca->delay_min >> 3)>>3, tp->snd_ssthresh, ca->delay_min, H, (ca->delay_min >>3) + H, ca->curr_rtt, ca->curr_rtt);	
			}
		}
	}
*/
}

/********************************************************************/
/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void golf_acked(struct sock *sk, u32 cnt, ktime_t last)
{

	u64 delay;
	last = last;
	struct golf *ca = inet_csk_ca(sk);
	const struct inet_connection_sock *icsk = inet_csk(sk);
	const struct tcp_sock *tp = tcp_sk(sk);

	if (cnt > 0 && icsk->icsk_ca_state == TCP_CA_Open) {
		//struct golf *ca = inet_csk_ca(sk);
		cnt -= ca->delayed_ack >> ACK_RATIO_SHIFT;
		ca->delayed_ack += cnt;
	}
	
	if (cnt > 0)
		ca->ww_rtt = (tcp_sk(sk)->srtt >> 3);

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

	delay = (tcp_time_stamp - tp->rx_opt.rcv_tsecr) << 3;
	if (delay == 0)
		delay = 1;



	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay){
		ca->delay_min = delay;
		ca->rtt.min = delay;
		ca->rtt.max = delay;
		ca->rtt_interval.min = delay;
		ca->rtt_interval.max = delay;
	}
	
/* update rtt for cdg */	
	if (ca->rtt.min > delay){
		ca->rtt.min = delay;	
		//ca->rtt_interval.min = delay;
	}
	if (ca->rtt.max < delay){
		ca->rtt.max = delay;	
		//ca->rtt_interval.max = delay;
	}
	if (ca->rtt_interval.max < delay){
		ca->rtt_interval.max = delay;
	}
	if (ca->rtt_interval.min > delay){
		ca->rtt_interval.min = delay;
	}
/* obtain the average of RTT within this rtt interval*/
	if (ca->rtt_count == 1){
		ca->rtt_average = 0;
		ca->rtt_count += 1;
	}
	else{
		//ca->rtt_average = (float)(ca->rtt_average / ca->rtt_count  * (ca->rtt_count-1)) + (float)(delay/ ca->rtt_count);
		ca->rtt_average = ca->rtt_average + delay;
		ca->rtt_count += 1;		
		//fprintf(stderr, "%lu    %lu    %lu\n", ca->rtt_average, delay, ca->rtt_count);
		}
	
	
	
	
	
/* update rtt for cdg */		

	/* hystart triggers when cwnd is larger than some threshold */
	if (hystart && ( tp->snd_cwnd < tp->snd_ssthresh ) &&
	    tp->snd_cwnd >= hystart_low_window)
	    hystart_update(sk, delay);
}
///////////////////////////////////////////////////////////////////////////////////////////////////////////////



static inline u32 westwood_acked_count(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct golf *w = inet_csk_ca(sk);

	w->ww_cumul_ack = tp->snd_una - w->ww_snd_una;

	/* If cumul_ack is 0 this is a dupack since it's not moving
	 * tp->snd_una.
	 */
	if (!w->ww_cumul_ack) {
		w->ww_accounted += tp->mss_cache;
		w->ww_cumul_ack = tp->mss_cache;
	}

	if (w->ww_cumul_ack > tp->mss_cache) {
		/* Partial or delayed ack */
		if (w->ww_accounted >= w->ww_cumul_ack) {
			w->ww_accounted -= w->ww_cumul_ack;
			w->ww_cumul_ack = tp->mss_cache;
		} else {
			w->ww_cumul_ack -= w->ww_accounted;
			w->ww_accounted = 0;
		}
	}

	w->ww_snd_una = tp->snd_una;

	return w->ww_cumul_ack;
}

static inline u32 westwood_do_filter(u32 a, u32 b)
{
	return (((7 * a) + b) >> 3);
}

static void westwood_filter(struct golf *w, u32 delta)
{
	/* If the filter is empty fill it with the first sample of bandwidth  */
	if (w->ww_bw_ns_est == 0 && w->ww_bw_est == 0) {
		w->ww_bw_ns_est = w->ww_bk / delta;
		w->ww_bw_est = w->ww_bw_ns_est;
	} else {
	
		//fprintf(stderr, "%lu  %lu\n",w->ww_bw_ns_est, w->ww_bk / delta );
		w->ww_bw_ns_est = westwood_do_filter(w->ww_bw_ns_est, w->ww_bk / delta);
		w->ww_bw_est = westwood_do_filter(w->ww_bw_est, w->ww_bw_ns_est);
	}
}


static void westwood_update_window(struct sock *sk)
{
	struct golf *w = inet_csk_ca(sk);
	s32 delta = tcp_time_stamp - w->ww_rtt_win_sx;

	/* Initialize w->snd_una with the first acked sequence number in order
	 * to fix mismatch between tp->snd_una and w->snd_una for the first
	 * bandwidth sample
	 */
	if (w->ww_first_ack) {
		w->ww_snd_una = tcp_sk(sk)->snd_una;
		w->ww_first_ack = 0;
	}

	/*
	 * See if a RTT-window has passed.
	 * Be careful since if RTT is less than
	 * 50ms we don't filter but we continue 'building the sample'.
	 * This minimum limit was chosen since an estimation on small
	 * time intervals is better to avoid...
	 * Obviously on a LAN we reasonably will always have
	 * right_bound = left_bound + WESTWOOD_RTT_MIN
	 */
	if (w->ww_rtt && delta > max_t(u32, w->ww_rtt, TCP_WESTWOOD_RTT_MIN)) {
		westwood_filter(w, delta);

//	last_bw_sample = 0;
//	stable_count = 0;
//	stable_flag = 0;

/*
		if (w->found & hystart_detect || 1){
			if ((float)w->last_bw_sample / (float)w->ww_bw_est > 0.95  &&  (float)w->last_bw_sample / (float)w->ww_bw_est < 1.0)
				w->stable_count = w->stable_count + 1;
			else if ((float)w->last_bw_sample / (float)w->ww_bw_est > 1){
				w->stable_count = w->stable_count - 1;
			}
			else{
				w->stable_count = 0;
				w->stable_flag = 0;
			}
			if (w->stable_count >= 5)
				w->stable_flag = 1;
			fprintf(stderr, "bandwidth: %lu  %lu   %lu   %lu    %lu   %f\n",w->ww_bw_est, w->last_bw_sample, w->stable_count, w->stable_flag, w->ww_bw_est - w->last_bw_sample, (float)w->last_bw_sample / (float)w->ww_bw_est );
		
			w->last_bw_sample = w->ww_bw_est;

		}
*/

//fprintf(stderr, "est: %lu   last: %lu   diff: %lu   perc: %f   time: %lu   bk: %lu, rtt: %lu  delta: %lu\n",w->ww_bw_est, w->last_bw_sample, w->ww_bw_est - w->last_bw_sample, (float)w->last_bw_sample / (float)w->ww_bw_est, tcp_time_stamp, w->ww_bk, w->ww_rtt, delta );
//fprintf(stderr, "%lu\n", w->ww_bw_est - w->last_bw_sample)	;
//fprintf(stderr, "%lu\n", w->ww_bw_est)	;
		w->last_bw_sample = w->ww_bw_est;

		//fprintf(stderr, "%lu   %lu   %lf    %lu    %lu   %lu    %lu\n", w->rtt_count, w->rtt_average, (float)w->rtt_average/w->rtt_count, w->rtt.min, w->rtt.max, w->rtt_interval.min, w->rtt_interval.max);
		w->rtt_interval.min = w->rtt_interval.min;
		w->rtt_interval.max = 0;
		w->ww_bk = 0;
		w->rtt_count = 1;
		
		w->ww_rtt_win_sx = tcp_time_stamp;
		
	}
}

static inline void update_rtt_min(struct golf *w)
{
	if (w->ww_reset_rtt_min) {
		w->ww_rtt_min = w->ww_rtt;
		w->ww_reset_rtt_min = 0;
	} else
		w->ww_rtt_min = min(w->ww_rtt, w->ww_rtt_min);
}

static inline void westwood_fast_bw(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	struct golf *w = inet_csk_ca(sk);

	westwood_update_window(sk);

	w->ww_bk += tp->snd_una - w->ww_snd_una;
	w->ww_snd_una = tp->snd_una;
	update_rtt_min(w);
}

static void tcp_golf_info(struct sock *sk, u32 ext, struct sk_buff *skb)
{
	sk = sk;
	ext = ext;
	skb = skb;
}

static u32 tcp_golf_bw_rttmin(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	const struct golf *w = inet_csk_ca(sk);
	return max_t(u32, (w->ww_bw_est * w->ww_rtt_min) / tp->mss_cache, 2);
}

static void tcp_golf_event(struct sock *sk, enum tcp_ca_event event)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct golf *w = inet_csk_ca(sk);

	switch (event) {
	case CA_EVENT_FAST_ACK:
		westwood_fast_bw(sk);
		//fprintf(stderr, "CA_EVENT_FAST_ACK\n");		
		break;

	case CA_EVENT_COMPLETE_CWR:
		tp->snd_cwnd = tp->snd_ssthresh = tcp_golf_bw_rttmin(sk);
		fprintf(stderr, "CA_EVENT_COMPLETE_CWR\n");	
		break;

	case CA_EVENT_FRTO:
		tp->snd_ssthresh = tcp_golf_bw_rttmin(sk);
		/* Update RTT_min when next ack arrives */
		w->ww_reset_rtt_min = 1;
		fprintf(stderr, "CA_EVENT_FRTO\n");	
		break;

	case CA_EVENT_SLOW_ACK:
		westwood_update_window(sk);
		w->ww_bk += westwood_acked_count(sk);
		update_rtt_min(w);
		//fprintf(stderr, "CA_EVENT_SLOW_ACK\n");
		// need to take care of this one, segmentation error
		break;

	default:
		/* don't care */
		break;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////////

/* a constant record for this congestion control algorithm */
static struct tcp_congestion_ops tcp_golf = {
// for cubic
	.init		= golf_init,
	.ssthresh	= golf_recalc_ssthresh,
	.cong_avoid	= golf_cong_avoid,
	.set_state	= golf_state,
	.undo_cwnd	= golf_undo_cwnd,
	.pkts_acked     = golf_acked,
	.owner		= THIS_MODULE,
	.name		= "golf",
// for westwood
	.cwnd_event	= tcp_golf_event,
	.get_info	= tcp_golf_info,
	.min_cwnd	= tcp_golf_bw_rttmin,
};


static int __init tcp_golf_register(void)
{
	BUILD_BUG_ON(sizeof(struct golf) > ICSK_CA_PRIV_SIZE);

	/* Precompute a bunch of the scaling factors that are used per-packet
	 * based on SRTT of 100ms
	 */

	beta_scale = 8*(BICTCP_BETA_SCALE+beta)/ 3 / (BICTCP_BETA_SCALE - beta);

	cube_rtt_scale = (bic_scale * 10);	/* 1024*c/rtt */

	/* calculate the "K" for (wmax-cwnd) = c/rtt * K^3
	 *  so K = cubic_root( (wmax-cwnd)*rtt/c )
	 * the unit of K is bictcp_HZ=2^10, not HZ
	 *
	 *  c = bic_scale >> 10
	 *  rtt = 100ms
	 *
	 * the following code has been designed and tested for
	 * cwnd < 1 million packets
	 * RTT < 100 seconds
	 * HZ < 1,000,00  (corresponding to 10 nano-second)
	 */

	/* 1/c * 2^2*bictcp_HZ * srtt */
	cube_factor = 1ull << (10+3*BICTCP_HZ); /* 2^40 */

	/* divide by bic_scale and by constant Srtt (100ms) */
	do_div(cube_factor, bic_scale * 10);

	return tcp_register_congestion_control(&tcp_golf);
}

static void __exit tcp_golf_unregister(void)
{
	tcp_unregister_congestion_control(&tcp_golf);
}

module_init(tcp_golf_register);
module_exit(tcp_golf_unregister);

MODULE_AUTHOR("Golf");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("GOLF TCP");
MODULE_VERSION("1.1");
#undef NS_PROTOCOL
