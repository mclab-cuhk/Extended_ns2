/* Modified Linux module source code from /home/weixl/linux-2.6.22.6 */
#define NS_PROTOCOL "tcp_cubic.c"
#include "../ns-linux-c.h"
#include "../ns-linux-util.h"
/*
 * TCP CUBIC: Binary Increase Congestion control for TCP v2.1
 *
 * This is from the implementation of CUBIC TCP in
 * Injong Rhee, Lisong Xu.
 *  "CUBIC: A New TCP-Friendly High-Speed TCP Variant
 *  in PFLDnet 2005
 * Available from:
 *  http://www.csc.ncsu.edu/faculty/rhee/export/bitcp/cubic-paper.pdf
 *
 * Unless CUBIC is enabled and congestion window is large
 * this behaves the same as the original Reno.
 */


#define BICTCP_BETA_SCALE    1024	/* Scale factor beta calculation
					 * max_cwnd = snd_cwnd * beta
					 */
#define BICTCP_B		4	 /*
					  * In binary search,
					  * go to point (max+min)/N
					  */
#define	BICTCP_HZ		10	/* BIC HZ 2^10 = 1024 */


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
static int beta __read_mostly = 717;	/* = 819/1024 (BICTCP_BETA_SCALE) */
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


/* BIC TCP Parameters */
struct bictcp {
	u32	cnt;		/* increase cwnd by 1 after ACKs */
	u32 	last_max_cwnd;	/* last maximum snd_cwnd */
	u32	loss_cwnd;	/* congestion window at last loss */
	u32	last_cwnd;	/* the last snd_cwnd */
	u32	last_time;	/* time when updated last_cwnd */
	u32	bic_origin_point;/* origin point of bic function */
	u32	bic_K;		/* time to origin point from the beginning of the current epoch */

	u32	delay_min;	/* min delay */
	u32	epoch_start;	/* beginning of an epoch */
	u32	ack_cnt;	/* number of acks */
	u32	tcp_cwnd;	/* estimated tcp cwnd */
//#define ACK_RATIO_SHIFT	4
//	u32	delayed_ack;	/* estimate the ratio of Packets/ACKs << 4 */

	u8	sample_cnt;	/* number of samples to decide curr_rtt */
	u8	found;		/* the exit point is found? */
	u32	round_start;	/* beginning of each round */
	u32	end_seq;	/* end_seq of the round */
	u32	last_ack;	/* last time when the ACK spacing is close */
	u32	curr_rtt;	/* the minimum rtt of current round */
//	u32    congestion_before; /* does congestion happen before ? */

};

static inline void bictcp_reset(struct bictcp *ca)
{
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
	ca->found = 0; // new

}


/********************************************************************/
static inline void bictcp_hystart_reset( u32 ack,u32 end_seq,  struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->round_start = ca->last_ack = tcp_time_stamp;
	ca->end_seq = tp->snd_nxt;
	ca->curr_rtt = 0;
	ca->sample_cnt = 0;
}
/********************************************************************/


static void bictcp_init(struct sock *sk)
{

/********************************************************************/
	struct bictcp *ca = inet_csk_ca(sk);

	bictcp_reset(ca);
	ca->loss_cwnd = 0;

	if (hystart)
		bictcp_hystart_reset(1, 1, sk);

	if (!hystart && initial_ssthresh)
		tcp_sk(sk)->snd_ssthresh = initial_ssthresh;
/********************************************************************/

}

/*
static void bictcp_cwnd_event(struct sock *sk, enum tcp_ca_event event)
{

	if (event == CA_EVENT_TX_START) {
		struct bictcp *ca = inet_csk_ca(sk);
		u32 now = tcp_time_stamp;
		s32 delta;

		delta = now - tcp_sk(sk)->lsndtime;

		    We were application limited (idle) for a while.
		    Shift epoch_start to keep cwnd growth to cubic curve.

		// in ns2, application limited will never happened(?) 
		if (ca->epoch_start && delta > 0) {
			ca->epoch_start += delta;
			if (after(ca->epoch_start, now))
				ca->epoch_start = now;
		}
		return;
	}
}
*/


/* calculate the cubic root of x using a table lookup followed by one
 * Newton-Raphson iteration.
 * Avg err ~= 0.195%
 */
// exactly the same as new one, keep it untouched
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

/*
 * Compute congestion window to use.
 */
static inline void bictcp_update(struct bictcp *ca, u32 cwnd)
{

	u64 offs;
	u32 delta, t, bic_target, min_cnt, max_cnt;

	ca->ack_cnt++;	/* count the number of ACKs */


	if (ca->last_cwnd == cwnd &&
	    (s32)(tcp_time_stamp - ca->last_time) <= HZ / 32)
		return;


	if (ca->epoch_start && tcp_time_stamp == ca->last_time)	//new
		goto tcp_friendliness;				//new


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

	/*
	 * The initial growth of cubic function may be too conservative
	 * when the available bandwidth is still unknown.
	 */
	if (ca->last_max_cwnd == 0 && ca->cnt > 20)
		ca->cnt = 20;	/* increase cwnd 5% per RTT */

//	fprintf(stderr, "update 2!  %d\n", ca->cnt);	


tcp_friendliness:
	/* TCP Friendly */
	if (tcp_friendliness) {
		u32 scale = beta_scale;

		delta = (cwnd * scale) >> 3;
		while (ca->ack_cnt > delta) {		/* update tcp cwnd */
			ca->ack_cnt -= delta;
			ca->tcp_cwnd++;
		}

		if (ca->tcp_cwnd > cwnd) {	/* if bic is slower than tcp */
			delta = ca->tcp_cwnd - cwnd;
			max_cnt = cwnd / delta;
			if (ca->cnt > max_cnt)
				ca->cnt = max_cnt;
		}
	}

	/* The maximum rate of cwnd increase CUBIC allows is 1 packet per
	 * 2 packets ACKed, meaning cwnd grows at 1.5x per RTT.
	 */
	ca->cnt = max(ca->cnt, 2U);
}

static void bictcp_cong_avoid(struct sock *sk, u32 ack,
			      u32 seq_rtt, u32 in_flight, int data_acked)
{
	u32 acked = data_acked;

	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	// new "tcp_is_cwnd_limited" implementation.
	if (tp->snd_cwnd < tp->snd_ssthresh){	//in slow start phase
		if (    !tcp_is_cwnd_limited(sk, in_flight * 2)   )
			return;
	}
	else{
		if (    !tcp_is_cwnd_limited(sk, in_flight)   )
			return;
	}

//	if (    !tcp_is_cwnd_limited(sk, in_flight)   ){
//		fprintf(stderr, "%d\n", in_flight);
//				return;
//	}

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

static u32 bictcp_recalc_ssthresh(struct sock *sk)
{

	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

	ca->epoch_start = 0;	/* end of epoch */

	/* Wmax and fast convergence */
	if (tp->snd_cwnd < ca->last_max_cwnd && fast_convergence)
		ca->last_max_cwnd = (tp->snd_cwnd * (BICTCP_BETA_SCALE + beta))
			/ (2 * BICTCP_BETA_SCALE);
	else
		ca->last_max_cwnd = tp->snd_cwnd;

	ca->loss_cwnd = tp->snd_cwnd;

	return max((tp->snd_cwnd * beta) / BICTCP_BETA_SCALE, 2U);
}

static u32 bictcp_undo_cwnd(struct sock *sk)
{
	struct bictcp *ca = inet_csk_ca(sk);

	return max(tcp_sk(sk)->snd_cwnd, ca->last_max_cwnd);
}

static void bictcp_state(struct sock *sk, u8 new_state)
{
	if (new_state == TCP_CA_Loss)
		bictcp_reset(inet_csk_ca(sk));
		bictcp_hystart_reset(1,1, sk);	// new 
}
 



/********************************************************************/

static void hystart_update(struct sock *sk, u32 delay)
{
	//fprintf(		stderr, "hystart_update000  %d\n", delay>>3);		

	struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);

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

}

/********************************************************************/



/* Track delayed acknowledgment ratio using sliding window
 * ratio = (15*ratio + sample) / 16
 */
static void bictcp_acked(struct sock *sk, u32 cnt, ktime_t last)
{

	const struct tcp_sock *tp = tcp_sk(sk);
	struct bictcp *ca = inet_csk_ca(sk);
	u64 delay;

	/* Discard delay samples right after fast recovery */
	if (ca->epoch_start && (s32)(tcp_time_stamp - ca->epoch_start) < HZ)
		return;

	delay = (tcp_time_stamp - tp->rx_opt.rcv_tsecr) << 3;
	if (delay == 0)
		delay = 1;

	/* first time call or link delay decreases */
	if (ca->delay_min == 0 || ca->delay_min > delay)
		ca->delay_min = delay;

	/* hystart triggers when cwnd is larger than some threshold */
	if (hystart && ( tp->snd_cwnd < tp->snd_ssthresh ) &&
	    tp->snd_cwnd >= hystart_low_window)
	    hystart_update(sk, delay);

/********************************************************************/

}


static struct tcp_congestion_ops cubictcp = {
	.init		= bictcp_init,
	.ssthresh	= bictcp_recalc_ssthresh,
	.cong_avoid	= bictcp_cong_avoid,
	.set_state	= bictcp_state,
	.undo_cwnd	= bictcp_undo_cwnd,
	.pkts_acked     = bictcp_acked,
	.owner		= THIS_MODULE,
	.name		= "golf2",
};

static int __init cubictcp_register(void)
{
	BUILD_BUG_ON(sizeof(struct bictcp) > ICSK_CA_PRIV_SIZE);

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

	return tcp_register_congestion_control(&cubictcp);
}

static void __exit cubictcp_unregister(void)
{
	tcp_unregister_congestion_control(&cubictcp);
}

module_init(cubictcp_register);
module_exit(cubictcp_unregister);

MODULE_AUTHOR("Sangtae Ha, Stephen Hemminger");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CUBIC TCP");
MODULE_VERSION("2.1");
#undef NS_PROTOCOL
