set ns [new Simulator]

# nam sim data
set nf [open out.nam w]
$ns namtrace-all $nf

set tf [open trace_ns2_new w]
$ns trace-all $tf

# cwnd data
set wf1 [open cwnd_ns2_new w]

# on finish
# flush all trace and open nam
proc finish {} {
    global ns  tf nf
    $ns flush-trace
    close $nf
    
    close $tf
   # exec xgraph cwnd_ns2_new -geometry 800x400 &
   # exec nam /home/ubuntu14/success_stateful_tcp/trace_data/out.nam &
    exit 0
}

# create nodes
set n0 [$ns node]
set n1 [$ns node]
set n2 [$ns node]
set n3 [$ns node]

# setup a simple topology as follows:
#
# n0 -- 
#       n1 ========== n2
# n3 --

$ns duplex-link $n0 $n1 10Mb 25ms DropTail	# this is the bottleneck
$ns duplex-link $n1 $n2 1000Mb 25ms DropTail
$ns duplex-link $n1 $n3 1000Mb 25ms DropTail
#$ns queue-limit $n0 $n1 30
$ns queue-limit $n1 $n2 100
# setup queue watcher and queue limit bet n2 and n3
$ns duplex-link-op $n1 $n2 queuePos 0.1

# setup nam positions
$ns duplex-link-op $n0 $n1 orient right-down
$ns duplex-link-op $n1 $n2 orient right
$ns duplex-link-op $n3 $n1 orient right-up
# setup simulation colors
$ns color 1 Blue

#set udp0 [new Agent/UDP]
#$udp0 set packetSize_ 500
#$udp0 set class_ 1
#$ns attach-agent $n3 $udp0


# Create a Poisson traffic source and attach it to udp0
#set Poi0 [new Application/Traffic/Poisson]
#$Poi0 set packetSize_ 1500
#$Poi0 set rate_ 0.1Mb
#$Poi0 attach-agent $udp0
#Create a Null agent (a traffic sink) and attach it to node n3
#set null0 [new Agent/Null]
#$ns attach-agent $n2 $null0
#$ns connect $udp0 $null0


# setup n0 to n3 connection
set tcp0 [new Agent/TCP/Linux]
$tcp0 set fid_ 1
$tcp0 set class_ 1
$tcp0 set window_ 20000
$tcp0 set timestamps_ true
$tcp0 set packetSize_ 1500
$ns at 0 "$tcp0 select_ca cubic"
$ns attach-agent $n0 $tcp0

set sink0 [new Agent/TCPSink/Sack1]
$sink0 set class_ 1
$sink0 set timestamps_ true
$ns attach-agent $n2 $sink0

# setup traffic
set ftp0 [new Application/FTP]
$ftp0 attach-agent $tcp0
$ftp0 set type_ FTP

$ns connect $tcp0 $sink0

######random losss
set em [new ErrorModel]
$em unit pkt
$em set rate_ 0.0000001    ;#  PER = 3%
$em ranvar [new RandomVariable/Uniform]
$em drop-target [new Agent/Null]
#attach the model to the link
#$ns link-lossmodel $em $n2 $n3


#$ns at 0.0 "$Poi0 start"
#$ns at 10 "$Poi0 stop"
$ns at 0.0 "$ftp0 start"
$ns at 10 "$ftp0 stop"

# setup proc for cwnd plotting
proc plotWindow {tcpSource1 file1} {
   global ns

   set time 0.01
   set now [$ns now]
   set cwnd1 [$tcpSource1 set cwnd_]

   puts $file1 "$now $cwnd1"
   $ns at [expr $now+$time] "plotWindow $tcpSource1 $file1" 
}

# setup plotting
$ns at 0.0 "plotWindow $tcp0 $wf1"

# when to stop
$ns at 10.0 "finish"

# starto!
$ns run
