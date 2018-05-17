#include <stdlib.h>
 
#include "random.h"
#include "trafgen.h"
#include "ranvar.h"
 
class Poisson_Traffic : public TrafficGenerator {
 public:
        Poisson_Traffic();
        virtual void timeout();
        virtual double next_interval(int&);
 
 protected:
       virtual void start();
        void init();
        double rate_;     /* Mean sending rate (b/s) */
        double interval_; /* Mean time between each packet generation (sec) */
        int seqno_;       /* Each generated packet has a unique sequence number */
        int maxpkts_;     /* No source can generate more than maxpkts_ packets */
};
 
static class PoissonTrafficClass : public TclClass {
 public:
        PoissonTrafficClass() : TclClass("Application/Traffic/Poisson") {}
        TclObject* create(int, const char*const*) {
                return (new Poisson_Traffic());
        }
} class_poisson_traffic;
 
Poisson_Traffic::Poisson_Traffic() : seqno_(0)
{
        bind_bw("rate_", &rate_);
        bind("interval_", &interval_);
        bind("packetSize_", &size_);
        bind("maxpkts_", &maxpkts_);
}
 
void Poisson_Traffic::init()
{
  /*
   * If the user did not specify a mean packet inter-generation time,
   * then calculate it based on the rate_ and the packetSize_
   */
  if (interval_ < 0.0)
    interval_ = (double)(size_ << 3) / (double)rate_;
 
  /*
   * Assign unique packet type ID to each packet sent by a Poisson
   * source.
   */
  if (agent_)
    agent_->set_pkttype(PT_POISSON);
}
 
void Poisson_Traffic::start()
{
  init();
  running_ = 1;
  timeout(); 
}
 
 
double Poisson_Traffic::next_interval(int& size)
{
   size = size_;
   if (++seqno_ < maxpkts_)
     return(Random::exponential(interval_));
   else
     return(-1);
}
 
void Poisson_Traffic::timeout()
{
        if(! running_)
                return;
        agent_->sendmsg(size_);
        nextPkttime_ = next_interval(size_);
        timer_.resched(nextPkttime_);
}
